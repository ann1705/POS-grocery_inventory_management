"""
Integration test (standard library only) that:
 - logs in as sales1
 - adds a product to cart
 - attempts to update quantity without admin auth (expect failure)
 - attempts to update quantity with admin auth (expect success)
 - attempts to remove item without admin auth (expect failure)
 - attempts to remove item with admin auth (expect success)

Run while the dev server (python app.py) is running.
"""
import http.cookiejar, urllib.request, urllib.parse, json, sys

BASE = 'http://127.0.0.1:5000'
LOGIN = BASE + '/login'
PRODUCTS_API = BASE + '/api/products/'
ADD_CART = BASE + '/api/add-to-cart'
UPDATE_CART = BASE + '/api/update-cart'
REMOVE_CART = BASE + '/api/remove-from-cart/'

SALES_USER = ('sales1', 'sales123')
ADMIN_USER = ('admin1', 'admin123')

def post_form(opener, url, data):
    data = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=data)
    return opener.open(req, timeout=5)

def post_json(opener, url, payload):
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={'Content-Type':'application/json'})
    return opener.open(req, timeout=5)

def main():
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    # login as sales
    print('Logging in as sales user...')
    post_form(opener, LOGIN, {'username': SALES_USER[0], 'password': SALES_USER[1]})

    # fetch categories to find a product
    # pick first category id by calling /api/products/1, but safer: try category 1..5
    prod = None
    for cid in range(1,6):
        try:
            resp = opener.open(PRODUCTS_API + str(cid), timeout=2)
            body = resp.read().decode('utf-8')
            arr = json.loads(body)
            if arr:
                prod = arr[0]
                break
        except Exception:
            continue

    if not prod:
        print('No product found in first 5 categories; ensure server has seeded products (run seed_admin_and_product.py)')
        sys.exit(2)

    pid = prod['id']
    print('Using product id', pid, prod['name'])

    # add to cart
    print('Adding product to cart as sales...')
    r = post_json(opener, ADD_CART, {'product_id': pid, 'quantity': 1})
    print('Add-to-cart status:', r.getcode(), r.read().decode('utf-8'))

    # try update without admin auth
    print('Attempting update without admin auth (expect 401/403)')
    try:
        r = post_json(opener, UPDATE_CART, {'product_id': pid, 'quantity': 3})
        print('Unexpected success:', r.getcode(), r.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        print('Expected failure:', e.code, e.read().decode('utf-8'))

    # try update with admin auth
    print('Attempting update with admin auth (expect success)')
    r = post_json(opener, UPDATE_CART, {'product_id': pid, 'quantity': 2, 'auth_username': ADMIN_USER[0], 'auth_password': ADMIN_USER[1]})
    print('Update with auth status:', r.getcode(), r.read().decode('utf-8'))

    # try remove without admin auth
    print('Attempting remove without admin auth (expect 401/403)')
    try:
        req = urllib.request.Request(REMOVE_CART + str(pid), data=b'{}', headers={'Content-Type':'application/json'})
        r = opener.open(req)
        print('Unexpected success remove:', r.getcode(), r.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        print('Expected failure remove:', e.code, e.read().decode('utf-8'))

    # try remove with admin auth
    print('Attempting remove with admin auth (expect success)')
    req = urllib.request.Request(REMOVE_CART + str(pid), data=json.dumps({'auth_username': ADMIN_USER[0], 'auth_password': ADMIN_USER[1]}).encode('utf-8'), headers={'Content-Type':'application/json'})
    r = opener.open(req)
    print('Remove with auth status:', r.getcode(), r.read().decode('utf-8'))

if __name__ == '__main__':
    main()
