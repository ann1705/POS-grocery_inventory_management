import sqlite3

DB = 'grocery_pos.db'

conn = sqlite3.connect(DB)
cur = conn.cursor()
cur.execute("PRAGMA table_info('sale')")
cols = [r[1] for r in cur.fetchall()]
if 'cashier_username' not in cols:
    print('Adding cashier_username column to sale table')
    cur.execute("ALTER TABLE sale ADD COLUMN cashier_username VARCHAR(80) DEFAULT ''")
    conn.commit()
else:
    print('cashier_username already present')
conn.close()
