from flask import Flask, jsonify, request, render_template
from scapy.all import get_if_list
import sqlite3
import db
import capture

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
db.init_db()   # make sure the table exists even before the first capture

def query(sql, params=()):
    conn = sqlite3.connect("packets.db")
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute(sql, params)]
    conn.close()
    return rows

@app.route("/")
def home():
    return render_template("index.html")

# ---------- Capture controls (used by the dashboard buttons) ----------
@app.route("/api/interfaces")
def interfaces():
    return jsonify(get_if_list())

@app.route("/api/start", methods=["POST"])
def start():
    iface = (request.get_json(silent=True) or {}).get("iface")
    try:
        capture.start_capture(iface)
    except Exception as e:
        return jsonify(error=str(e)), 500
    return jsonify(running=capture.is_running())

@app.route("/api/stop", methods=["POST"])
def stop():
    capture.stop_capture()
    return jsonify(running=False)

@app.route("/api/clear", methods=["POST"])
def clear():
    db.clear_packets()
    return jsonify(ok=True)

@app.route("/api/status")
def status():
    return jsonify(running=capture.is_running())

# ---------- Data for the dashboard ----------
@app.route("/api/packets")
def packets():
    protocol = request.args.get("protocol", "")
    ip = request.args.get("ip", "")

    sql = "SELECT * FROM packets WHERE 1=1"
    params = []
    if protocol:
        sql += " AND protocol = ?"
        params.append(protocol.upper())
    if ip:
        sql += " AND (src_ip = ? OR dst_ip = ?)"
        params += [ip, ip]
    sql += " ORDER BY id DESC LIMIT 100"

    return jsonify(query(sql, params))

@app.route("/api/stats")
def stats():
    totals = query("SELECT COUNT(*) AS total, COALESCE(SUM(size), 0) AS bytes FROM packets")[0]
    by_protocol = query(
        "SELECT protocol, COUNT(*) AS count FROM packets "
        "GROUP BY protocol ORDER BY count DESC")
    top_sources = query(
        "SELECT src_ip AS ip, COUNT(*) AS count FROM packets "
        "WHERE src_ip IS NOT NULL GROUP BY src_ip ORDER BY count DESC LIMIT 5")
    return jsonify(total=totals["total"], total_bytes=totals["bytes"],
                   by_protocol=by_protocol, top_sources=top_sources)

if __name__ == "__main__":
    app.run(debug=False)