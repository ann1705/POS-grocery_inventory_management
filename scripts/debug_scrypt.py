import sqlite3, os, base64, binascii, hashlib, re
base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
db_path = os.path.join(base, 'instance', 'grocery_pos.db')
conn = sqlite3.connect(db_path)
cur = conn.cursor()
cur.execute("SELECT username, password FROM user WHERE username='superadmin'")
row = cur.fetchone()
if not row:
    print('superadmin not found')
    exit(1)
user, stored = row
print('stored:', stored)
m = re.match(r'^scrypt:(\d+):(\d+):(\d+)\$(.+)\$(.+)$', stored)
if not m:
    print('not match')
    exit(1)
N = int(m.group(1)); r = int(m.group(2)); p = int(m.group(3))
salt_str = m.group(4)
dk_hex = m.group(5).replace('\n','').replace('\r','')
print('N,r,p=',N,r,p)
print('salt_str=',salt_str)
print('dk_hex=',dk_hex[:64], 'len', len(dk_hex))
tries = {}
# try utf-8
try:
    salt = salt_str.encode('utf-8')
    dk = hashlib.scrypt(password='superadmin123'.encode('utf-8'), salt=salt, n=N, r=r, p=p)
    tries['utf8'] = dk.hex()
except Exception as e:
    tries['utf8_error'] = str(e)
# try base64 b64decode
try:
    salt = base64.b64decode(salt_str)
    dk = hashlib.scrypt(password='superadmin123'.encode('utf-8'), salt=salt, n=N, r=r, p=p)
    tries['b64'] = dk.hex()
except Exception as e:
    tries['b64_error'] = str(e)
# try urlsafe_b64
try:
    salt = base64.urlsafe_b64decode(salt_str)
    dk = hashlib.scrypt(password='superadmin123'.encode('utf-8'), salt=salt, n=N, r=r, p=p)
    tries['urlsafe_b64'] = dk.hex()
except Exception as e:
    tries['urlsafe_error'] = str(e)
# try hex
try:
    salt = bytes.fromhex(salt_str)
    dk = hashlib.scrypt(password='superadmin123'.encode('utf-8'), salt=salt, n=N, r=r, p=p)
    tries['hex'] = dk.hex()
except Exception as e:
    tries['hex_error'] = str(e)

for k,v in tries.items():
    print(k, ':', v[:64] if isinstance(v,str) else v)

# compare with stored dk
try:
    stored_dk = bytes.fromhex(dk_hex)
    print('stored_dk_hex[:64]=', stored_dk.hex()[:64])
except Exception as e:
    print('stored dk decode error', e)

conn.close()
