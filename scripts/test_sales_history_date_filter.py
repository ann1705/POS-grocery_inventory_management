"""Simple smoke test for sales history date filter.
Creates sample sales on three dates, logs in as superadmin, and requests /sales/history?date=...
"""
from datetime import datetime, timedelta
from app import app, db, Sale, SaleItem, User, Product, init_db
from sqlalchemy import func

# Prepare sample data
with app.app_context():
    init_db()

    admin = User.query.filter_by(username='superadmin').first()
    if not admin:
        admin = User(username='superadmin', password='', role='superadmin')
        db.session.add(admin)
        db.session.commit()

    product = Product.query.first()
    if not product:
        cat = None
        from app import Category
        cat = Category.query.first()
        if not cat:
            cat = Category(name='Test', description='test')
            db.session.add(cat)
            db.session.commit()
        product = Product(name='Sample', category_id=cat.id, price=10.0, stock=100)
        db.session.add(product)
        db.session.commit()

    # Create three sales for today, yesterday, and two days ago
    today = datetime.utcnow().date()
    dates = [today, today - timedelta(days=1), today - timedelta(days=2)]

    # Only create if not present (idempotent)
    for d in dates:
        # check if a sale exists on that date
        existing = Sale.query.filter(func.date(Sale.sale_date) == d.strftime('%Y-%m-%d')).first()
        if existing:
            continue
        sale = Sale(user_id=admin.id, cashier_username=admin.username, total_amount=10.0, total_items=1, sale_date=datetime(d.year, d.month, d.day, 12, 0, 0))
        db.session.add(sale)
        db.session.flush()
        si = SaleItem(sale_id=sale.id, product_id=product.id, quantity=1, price=product.price)
        db.session.add(si)
    db.session.commit()

# Now use test client to login and query pages
with app.test_client() as client:
    login_res = client.post('/login', data={'username': 'superadmin', 'password': 'superadmin123'}, follow_redirects=True)
    print('login status', login_res.status_code)

    for d in dates:
        date_str = d.strftime('%Y-%m-%d')
        res = client.get(f'/sales/history?date={date_str}')
        print(f'GET /sales/history?date={date_str} ->', res.status_code)
        if res.status_code == 200:
            content = res.get_data(as_text=True)
            found = 'Sales for' in content or 'No sales found' not in content
            print('  page length', len(content), 'contains sales table?', 'Sales for' in content)

    # Also check all-dates view
    res_all = client.get('/sales/history?date=all')
    print('GET all dates ->', res_all.status_code)
    if res_all.status_code == 200:
        print('  all-dates page length', len(res_all.get_data(as_text=True)))
