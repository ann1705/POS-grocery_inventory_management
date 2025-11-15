"""Smoke test for monthly sales history view.
Seeds a sale in two different months and requests the monthly view.
"""
from datetime import datetime
from app import app, db, Sale, SaleItem, User, Product, Category, init_db
from sqlalchemy import func

with app.app_context():
    init_db()

    admin = User.query.filter_by(username='superadmin').first()
    if not admin:
        admin = User(username='superadmin', password='', role='superadmin')
        db.session.add(admin)
        db.session.commit()

    cat = Category.query.first()
    if not cat:
        cat = Category(name='Seeds', description='test')
        db.session.add(cat)
        db.session.commit()

    product = Product.query.first()
    if not product:
        product = Product(name='MonthlySample', category_id=cat.id, price=5.0, stock=50)
        db.session.add(product)
        db.session.commit()

    # create a sale in Sept 2025 and Nov 2025 (if not present)
    def ensure_sale_on(date_obj):
        existing = Sale.query.filter(func.date(Sale.sale_date) == date_obj.strftime('%Y-%m-%d')).first()
        if existing:
            return
        s = Sale(user_id=admin.id, cashier_username=admin.username, month=date_obj.strftime('%B'), year=date_obj.year,
                 total_amount=5.0, total_items=1, sale_date=datetime(date_obj.year, date_obj.month, date_obj.day, 10, 0, 0))
        db.session.add(s)
        db.session.flush()
        si = SaleItem(sale_id=s.id, product_id=product.id, quantity=1, price=product.price)
        db.session.add(si)

    ensure_sale_on(datetime(2025,9,15).date())
    ensure_sale_on(datetime(2025,11,14).date())
    db.session.commit()

with app.test_client() as client:
    client.post('/login', data={'username':'superadmin','password':'superadmin123'})
    res_sep = client.get('/sales/history?ym=2025-09')
    print('Sep 2025 status', res_sep.status_code)
    res_nov = client.get('/sales/history?ym=2025-11')
    print('Nov 2025 status', res_nov.status_code)
    res_all = client.get('/sales/history?date=all')
    print('All dates status', res_all.status_code)
