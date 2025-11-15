from app import app, db, User, Category, Product
from werkzeug.security import generate_password_hash

with app.app_context():
    # create admin user
    admin_username = 'admin1'
    if not User.query.filter_by(username=admin_username).first():
        admin = User(username=admin_username, password=generate_password_hash('admin123'), role='admin')
        db.session.add(admin)
        print('Created admin user:', admin_username)
    else:
        print('Admin user already exists')

    # create category
    cat_name = 'Groceries'
    cat = Category.query.filter_by(name=cat_name).first()
    if not cat:
        cat = Category(name=cat_name, description='Grocery items')
        db.session.add(cat)
        db.session.flush()
        print('Created category:', cat.name, 'id=', cat.id)
    else:
        print('Category exists:', cat.name, 'id=', cat.id)

    # create product
    prod_name = 'Apple'
    prod = Product.query.filter_by(name=prod_name).first()
    if not prod:
        prod = Product(name=prod_name, category_id=cat.id, price=12.5, stock=50)
        db.session.add(prod)
        db.session.commit()
        print('Created product:', prod.name, 'id=', prod.id)
    else:
        print('Product exists:', prod.name, 'id=', prod.id)
