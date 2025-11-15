import http.cookiejar, urllib.request, urllib.parse

LOGIN='http://127.0.0.1:5000/login'
CHECKOUT='http://127.0.0.1:5000/sales/checkout'
USERNAME='admin1'
PASSWORD='admin123'

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
data = urllib.parse.urlencode({'username': USERNAME, 'password': PASSWORD}).encode()
req = urllib.request.Request(LOGIN, data=data)
resp = opener.open(req, timeout=5)
print('login status', resp.getcode())
resp2 = opener.open(CHECKOUT, timeout=5)
print('checkout status', resp2.getcode())
body = resp2.read().decode('utf-8', errors='ignore')
print('checkout page snippet:\n', body[:800])
