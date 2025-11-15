import sqlite3
c=sqlite3.connect('grocery_pos.db')
cur=c.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
print(cur.fetchall())
c.close()
