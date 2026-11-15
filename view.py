import sqlite3

conn = sqlite3.connect("packets.db")
print("Total packets:", conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0])
for row in conn.execute("SELECT protocol, COUNT(*) FROM packets GROUP BY protocol"):
    print(row)