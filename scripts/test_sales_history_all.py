import http.cookiejar, urllib.request, urllib.parse

LOGIN='http://127.0.0.1:5000/login'
HISTORY='http://127.0.0.1:5000/sales/history'
USERNAME='sales1'
PASSWORD='sales123'

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
data = urllib.parse.urlencode({'username': USERNAME, 'password': PASSWORD}).encode()
req = urllib.request.Request(LOGIN, data=data)
resp = opener.open(req, timeout=5)
print('login status', resp.getcode())
resp2 = opener.open(HISTORY, timeout=5)
print('history status', resp2.getcode())
body = resp2.read().decode('utf-8', errors='ignore')
print('history page snippet:\n', body[:800])
