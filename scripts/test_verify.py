import sqlite3, os, re, base64, hashlib

def verify_password(stored_hash, password):
    if not stored_hash or not password:
        return False
    if isinstance(stored_hash, str) and stored_hash.startswith('scrypt:'):
        m = re.match(r'^scrypt:(\d+):(\d+):(\d+)\$(.+)\$(.+)$', stored_hash)
        if not m:
            return False
        try:
            N = int(m.group(1))
            r = int(m.group(2))
            p = int(m.group(3))
            salt_str = m.group(4)
            dk_hex = m.group(5).replace('\n','').replace('\r','')
            try:
                salt = base64.b64decode(salt_str)
            except Exception:
                salt = salt_str.encode('utf-8')
            try:
                dk_stored = bytes.fromhex(dk_hex)
            except Exception:
                try:
                    dk_stored = base64.b64decode(dk_hex)
                except Exception:
                    return False
            dk = hashlib.scrypt(password=password.encode('utf-8'), salt=salt, n=N, r=r, p=p)
            return hashlib.compare_digest(dk, dk_stored)
        except Exception:
            return False
    return False

base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
db_path = os.path.join(base, 'instance', 'grocery_pos.db')
if not os.path.exists(db_path):
    print('DB not found:', db_path)
    exit(1)
conn = sqlite3.connect(db_path)
cur = conn.cursor()
cur.execute("SELECT username, password FROM user")
for u,p in cur.fetchall():
    ok = verify_password(p, 'superadmin123')
    print(u, '-> verify with superadmin123:', ok)
    ok2 = verify_password(p, 'wrongpassword')
    print(u, '-> verify with wrongpassword:', ok2)
conn.close()
