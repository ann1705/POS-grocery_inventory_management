import sqlite3
import os
base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
db_path = os.path.join(base, 'instance', 'grocery_pos.db')
if not os.path.exists(db_path):
    print('DB not found:', db_path)
    exit(1)
conn = sqlite3.connect(db_path)
cur = conn.cursor()
try:
    cur.execute('SELECT id, username, password, role FROM user')
    rows = cur.fetchall()
    for r in rows:
        print('ID:', r[0])
        print('Username:', r[1])
        print('Password:', r[2])
        print('Role:', r[3])
        print('---')
except Exception as e:
    print('Error reading users:', e)
finally:
    conn.close()
