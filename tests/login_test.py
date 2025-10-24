# Simple test script to check superadmin can login and access /admin/dashboard
# Tries to use requests if available, otherwise falls back to urllib
import sys
import time

LOGIN_URL = 'http://127.0.0.1:5000/login'
ADMIN_URL = 'http://127.0.0.1:5000/admin/dashboard'
USERNAME = 'superadmin'
PASSWORD = 'superadmin123'

try:
    import requests
    s = requests.Session()
    print('Using requests module')
    r = s.post(LOGIN_URL, data={'username': USERNAME, 'password': PASSWORD}, allow_redirects=True, timeout=5)
    print('Login POST status:', r.status_code)
    r2 = s.get(ADMIN_URL, timeout=5)
    print('Admin GET status:', r2.status_code)
    if r2.status_code == 200 and 'Admin Dashboard' in r2.text:
        print('SUCCESS: superadmin can access admin dashboard')
    else:
        print('FAIL: unexpected response or missing Admin Dashboard content')
except Exception as e:
    print('Requests path failed or not available:', e)
    print('Falling back to urllib...')
    try:
        import http.cookiejar, urllib.request, urllib.parse
        cj = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
        data = urllib.parse.urlencode({'username': USERNAME, 'password': PASSWORD}).encode()
        req = urllib.request.Request(LOGIN_URL, data=data)
        resp = opener.open(req, timeout=5)
        print('Login POST status:', resp.getcode())
        resp2 = opener.open(ADMIN_URL, timeout=5)
        body = resp2.read().decode('utf-8', errors='ignore')
        print('Admin GET status:', resp2.getcode())
        if resp2.getcode() == 200 and 'Admin Dashboard' in body:
            print('SUCCESS: superadmin can access admin dashboard')
        else:
            print('FAIL: unexpected response or missing Admin Dashboard content')
    except Exception as e2:
        print('Fallback urllib test failed:', e2)
        sys.exit(2)

# keep process alive shortly to ensure logs flush
time.sleep(0.2)
