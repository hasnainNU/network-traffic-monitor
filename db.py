import sqlite3

DB_FILE = "packets.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_mac TEXT,
            dst_mac TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            size INTEGER,
            info TEXT
        )
    """)
    conn.commit()
    conn.close()

def insert_packet(row):
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        """INSERT INTO packets
           (timestamp, src_mac, dst_mac, src_ip, dst_ip,
            src_port, dst_port, protocol, size, info)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        row,
    )
    conn.commit()
    conn.close()

def clear_packets():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("DELETE FROM packets")
    conn.commit()
    conn.close()