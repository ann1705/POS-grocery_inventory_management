from flask import Flask, flash, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, date
from functools import wraps
from sqlalchemy import func, text
from sqlalchemy.orm import backref
import os
import hashlib
import base64
import re

app = Flask(__name__)
# Compute an absolute path to the instance DB so the app works regardless of current working directory.
base_dir = os.path.dirname(os.path.abspath(__file__))
instance_dir = os.path.join(base_dir, 'instance')
# Ensure instance directory exists
os.makedirs(instance_dir, exist_ok=True)
instance_db_path = os.path.join(instance_dir, 'grocery_pos.db')
# Normalize to forward slashes for the URI on Windows
instance_db_uri = f"sqlite:///{instance_db_path.replace('\\\\','/') }"
# Allow overriding with env var, otherwise use absolute instance path
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', instance_db_uri)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-me-dev-only')
db = SQLAlchemy(app)

# ==================== MODELS ====================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    products = db.relationship('Product', backref='category', lazy=True, cascade='all, delete-orphan')

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, default=0)
    image_url = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    inventory_records = db.relationship('Inventory', backref='product', lazy=True, cascade='all, delete-orphan')

class Sale(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    cashier_username = db.Column(db.String(80), nullable=False)
    month = db.Column(db.String(20))
    year = db.Column(db.Integer)
    total_amount = db.Column(db.Float, nullable=False)
    total_items = db.Column(db.Integer, nullable=False)
    sale_date = db.Column(db.DateTime, default=datetime.now)
    items = db.relationship('SaleItem', backref='sale', lazy=True, cascade='all, delete-orphan')
    user = db.relationship('User', backref=backref('sales', cascade='all, delete-orphan'))

class SaleItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sale_id = db.Column(db.Integer, db.ForeignKey('sale.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    product = db.relationship('Product')

class Inventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity_sold = db.Column(db.Integer, nullable=False)
    quantity_remaining = db.Column(db.Integer, nullable=False)
    record_date = db.Column(db.DateTime, default=datetime.utcnow)
    month = db.Column(db.String(20))
    year = db.Column(db.Integer)

# ==================== DECORATORS ====================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            user = User.query.get(session['user_id'])
            if user.role not in roles and user.role != 'superadmin':
                return redirect(url_for('unauthorized'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def verify_password(stored_hash, password):
    """Verify password supporting werkzeug hashes and scrypt-style hashes stored as:
    scrypt:N:r:p$<salt>$<hex_dk>
    Falls back to werkzeug.check_password_hash for other formats.
    """
    if not stored_hash or not password:
        return False

    # scrypt format starting with 'scrypt:'
    if isinstance(stored_hash, str) and stored_hash.startswith('scrypt:'):
        # pattern: scrypt:N:r:p$salt$dk
        m = re.match(r'^scrypt:(\d+):(\d+):(\d+)\$(.+)\$(.+)$', stored_hash)
        if not m:
            return False
        try:
            N = int(m.group(1))
            r = int(m.group(2))
            p = int(m.group(3))
            salt_str = m.group(4)
            dk_hex = m.group(5).replace('\n','').replace('\r','')

            # Try decoding salt as base64, fallback to raw utf-8 bytes
            try:
                salt = base64.b64decode(salt_str)
            except Exception:
                salt = salt_str.encode('utf-8')

            # Derived key from stored hash (hex)
            try:
                dk_stored = bytes.fromhex(dk_hex)
            except Exception:
                # If not hex, try base64
                try:
                    dk_stored = base64.b64decode(dk_hex)
                except Exception:
                    return False

            # Compute scrypt derived key
            dk = hashlib.scrypt(password=password.encode('utf-8'), salt=salt, n=N, r=r, p=p)
            return hashlib.compare_digest(dk, dk_stored)
        except Exception:
            return False

    # Fallback to werkzeug
    return check_password_hash(stored_hash, password)


# ==================== ROUTES ====================

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for("login"))
    user = User.query.get(session['user_id'])
    
    if user.role == 'superadmin':
        return redirect(url_for('superadmin_dashboard'))
    elif user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('pos'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and verify_password(user.password, password):
            session['user'] = user.username
            session['username'] = user.username
            session['user_id'] = user.id
            session['role'] = user.role
            session['cart'] = []
            flash("Login successful!", "success")
            return redirect(url_for('index'))
        else:
            flash("Invalid username or password", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/unauthorized')
def unauthorized():
    return render_template('unauthorized.html'), 403

# ==================== SUPERADMIN ROUTES ====================

@app.route('/superadmin/dashboard')
@role_required('superadmin')
def superadmin_dashboard():
    admins = User.query.filter_by(role='admin').all()
    sales_users = User.query.filter_by(role='sales').all()
    # include categories and cart so superadmin can also access POS-like view
    categories = Category.query.all()
    cart = session.get('cart', [])
    return render_template('superadmin_dashboard.html', admins=admins, sales_users=sales_users,
                           categories=categories, cart=cart)

@app.route('/superadmin/add-user', methods=['GET', 'POST'])
@role_required('superadmin')
def add_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        
        if User.query.filter_by(username=username).first():
            return render_template('add_user.html', error='Username already exists')
        
        user = User(username=username, password=generate_password_hash(password), role=role)
        db.session.add(user)
        db.session.commit()
        flash(f'User {username} created successfully!', 'success')
        return redirect(url_for('superadmin_dashboard'))
    
    return render_template('add_user.html')

@app.route('/superadmin/delete-user/<int:user_id>', methods=['POST'])
@role_required('superadmin')
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f'User deleted successfully!', 'success')
    return redirect(url_for('superadmin_dashboard'))

# ==================== ADMIN ROUTES ====================

@app.route('/admin/dashboard')
@role_required('admin')
def admin_dashboard():
    categories = Category.query.all()
    products = Product.query.all()
    total_stock = sum(p.stock for p in products)
    low_stock = Product.query.filter(Product.stock < 10).count()
    # include cart so admin can see the POS split view (categories + cart)
    cart = session.get('cart', [])
    return render_template('admin_dashboard.html', 
                         categories=categories, 
                         products=products,
                         total_stock=total_stock,
                         low_stock=low_stock,
                         cart=cart)

@app.route('/admin/categories', methods=['GET', 'POST'])
@role_required('admin')
def manage_categories():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        
        if Category.query.filter_by(name=name).first():
            categories = Category.query.all()
            return render_template('manage_categories.html', categories=categories, error='Category already exists')
        
        category = Category(name=name, description=description)
        db.session.add(category)
        db.session.commit()
        flash('Category added successfully!', 'success')
        return redirect(url_for('manage_categories'))
    
    categories = Category.query.all()
    return render_template('manage_categories.html', categories=categories)

@app.route('/admin/categories/<int:cat_id>/edit', methods=['GET', 'POST'])
@role_required('admin')
def edit_category(cat_id):
    category = Category.query.get_or_404(cat_id)
    if request.method == 'POST':
        category.name = request.form.get('name')
        category.description = request.form.get('description')
        db.session.commit()
        flash('Category updated successfully!', 'success')
        return redirect(url_for('manage_categories'))
    return render_template('edit_category.html', category=category)

@app.route('/admin/categories/<int:cat_id>/delete', methods=['POST'])
@role_required('admin')
def delete_category(cat_id):
    category = Category.query.get_or_404(cat_id)
    db.session.delete(category)
    db.session.commit()
    flash('Category deleted successfully!', 'success')
    return redirect(url_for('manage_categories'))

@app.route('/admin/products', methods=['GET', 'POST'])
@role_required('admin')
def manage_products():
    if request.method == 'POST':
        name = request.form.get('name')
        category_id = request.form.get('category_id')
        price = request.form.get('price')
        stock = request.form.get('stock')
        image_url = request.form.get('image_url')
        
        product = Product(name=name, category_id=category_id, price=price, stock=stock, image_url=image_url)
        db.session.add(product)
        db.session.commit()
        flash('Product added successfully!', 'success')
        return redirect(url_for('manage_products'))
    
    categories = Category.query.all()
    products = Product.query.all()
    return render_template('manage_products.html', categories=categories, products=products)

@app.route('/admin/products/<int:prod_id>/edit', methods=['GET', 'POST'])
@role_required('admin')
def edit_product(prod_id):
    product = Product.query.get_or_404(prod_id)
    if request.method == 'POST':
        product.name = request.form.get('name')
        product.category_id = request.form.get('category_id')
        product.price = request.form.get('price')
        product.stock = request.form.get('stock')
        product.image_url = request.form.get('image_url')
        db.session.commit()
        flash('Product updated successfully!', 'success')
        return redirect(url_for('manage_products'))
    
    categories = Category.query.all()
    return render_template('edit_product.html', product=product, categories=categories)

@app.route('/admin/products/<int:prod_id>/delete', methods=['POST'])
@role_required('admin')
def delete_product(prod_id):
    product = Product.query.get_or_404(prod_id)
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully!', 'success')
    return redirect(url_for('manage_products'))


@app.route('/admin/add-sales', methods=['GET', 'POST'])
@role_required('admin')
def admin_add_sales():
    # Admin (and superadmin via role_required) can create sales accounts
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = 'sales'
        if User.query.filter_by(username=username).first():
            return render_template('add_user.html', error='Username already exists', role_suggest=role)
        user = User(username=username, password=generate_password_hash(password), role=role)
        db.session.add(user)
        db.session.commit()
        flash(f'Sales user {username} created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    # reuse add_user.html but suggest role= sales
    return render_template('add_user.html', role_suggest='sales')

@app.route('/admin/inventory')
@role_required('admin')
def view_inventory():
    month_filter = request.args.get('month')
    year_filter = request.args.get('year')
    category_filter = request.args.get('category')
    date_filter = request.args.get('date')
    
    months = ['January', 'February', 'March', 'April', 'May', 'June',
              'July', 'August', 'September', 'October', 'November', 'December']

    years_query = db.session.query(Inventory.year).distinct().order_by(Inventory.year.asc()).all()
    years = [y[0] for y in years_query if y[0] is not None]

    query = Inventory.query
    if month_filter:
        query = query.filter_by(month=month_filter)
    if year_filter:
        try:
            query = query.filter_by(year=int(year_filter))
        except ValueError:
            pass
    if date_filter:
        try:
            datetime.strptime(date_filter, '%Y-%m-%d')
            query = query.filter(func.date(Inventory.record_date) == date_filter)
        except ValueError:
            pass

    inventory = None
    if category_filter:
        try:
            cat_id = int(category_filter)
            products = Product.query.filter_by(category_id=cat_id).order_by(Product.name).all()
            inventory = []
            for p in products:
                inv_q = Inventory.query.filter_by(product_id=p.id)
                if month_filter:
                    inv_q = inv_q.filter_by(month=month_filter)
                if year_filter:
                    try:
                        inv_q = inv_q.filter_by(year=int(year_filter))
                    except ValueError:
                        pass
                if date_filter:
                    try:
                        datetime.strptime(date_filter, '%Y-%m-%d')
                        inv_q = inv_q.filter(func.date(Inventory.record_date) == date_filter)
                    except ValueError:
                        pass
                qty_sold = sum(i.quantity_sold for i in inv_q.all())
                inventory.append({
                    'product': p,
                    'quantity_sold': qty_sold,
                    'quantity_remaining': p.stock,
                    'month': month_filter,
                    'year': int(year_filter) if year_filter and year_filter.isdigit() else None,
                    'date': date_filter
                })
        except ValueError:
            pass

    if inventory is None:
        if category_filter:
            try:
                cat_id = int(category_filter)
                query = query.join(Product).filter(Product.category_id == cat_id)
            except ValueError:
                pass
        inventory = query.all()
    
    categories = Category.query.order_by(func.lower(Category.name)).all()
    return render_template('inventory.html', inventory=inventory, categories=categories, 
                         month_filter=month_filter, category_filter=category_filter, 
                         months=months, years=years, year_filter=year_filter, date_filter=date_filter)

# ==================== POS ROUTES (FOR ALL ROLES) ====================

@app.route('/pos')
@login_required
def pos():
    categories = Category.query.all()
    cart = session.get('cart', [])
    return render_template('pos.html', categories=categories, cart=cart)

@app.route('/sales/home')
@role_required('sales')
def home():
    return redirect(url_for('pos'))

@app.route('/api/products/<int:cat_id>')
@login_required
def get_products(cat_id):
    products = Product.query.filter_by(category_id=cat_id).all()
    return jsonify([{
        'id': p.id,
        'name': p.name,
        'price': p.price,
        'stock': p.stock,
        'image_url': p.image_url
    } for p in products])

@app.route('/api/product/<int:product_id>')
@login_required
def get_product(product_id):
    product = Product.query.get_or_404(product_id)
    return jsonify({
        'id': product.id,
        'name': product.name,
        'price': product.price,
        'stock': product.stock,
        'image_url': product.image_url,
        'category_id': product.category_id
    })

@app.route('/sales/checkout')
@role_required('sales', 'admin')
def checkout():
    # Render a dedicated checkout page showing the current cart and totals.
    cart = session.get('cart', [])
    
    # Fetch product details for each cart item from the database
    enriched_cart = []
    total_amount = 0
    total_items = 0
    
    for item in cart:
        product = Product.query.get(item['product_id'])
        if product:
            quantity = item['quantity']
            enriched_item = {
                'id': product.id,
                'product_id': product.id,
                'name': product.name,
                'price': product.price,
                'quantity': quantity
            }
            enriched_cart.append(enriched_item)
            total_amount += quantity * product.price
            total_items += quantity
    
    date_for_checkout = datetime.now().strftime('%Y-%m-%d')
    return render_template('checkout.html', cart=enriched_cart, total_amount=total_amount, total_items=total_items, date_for_checkout=date_for_checkout)

@app.route('/api/add-to-cart', methods=['POST'])
@login_required
def add_to_cart():
    data = request.get_json()
    product_id = data.get('product_id')
    quantity = int(data.get('quantity'))
    
    product = Product.query.get_or_404(product_id)
    
    if product.stock < quantity:
        return jsonify({'success': False, 'message': 'Insufficient stock'}), 400
    
    # Store only product_id and quantity in session (minimal size to avoid cookie overflow)
    cart = session.get('cart', [])
    
    item_exists = False
    for item in cart:
        if item['product_id'] == product_id:
            if product.stock < item['quantity'] + quantity:
                return jsonify({'success': False, 'message': 'Insufficient stock'}), 400
            item['quantity'] += quantity
            item_exists = True
            break
    
    if not item_exists:
        cart.append({
            'product_id': product_id,
            'quantity': quantity
        })
    
    session['cart'] = cart
    session.modified = True
    return jsonify({'success': True, 'message': 'Item added to cart'})

@app.route('/api/update-cart', methods=['POST'])
@login_required
def update_cart():
    data = request.get_json()
    product_id = data.get('product_id')
    quantity = int(data.get('quantity'))
    
    if quantity < 1:
        return jsonify({'success': False, 'message': 'Quantity must be at least 1'}), 400
    
    product = Product.query.get_or_404(product_id)
    
    if product.stock < quantity:
        return jsonify({'success': False, 'message': 'Insufficient stock'}), 400

    # If the current user is a sales user, require admin/superadmin authentication to change quantities
    if session.get('role') == 'sales':
        auth_username = data.get('auth_username')
        auth_password = data.get('auth_password')
        if not auth_username or not auth_password:
            return jsonify({'success': False, 'message': 'Admin credentials required to update cart'}), 401
        auth_user = User.query.filter_by(username=auth_username).first()
        if not auth_user or auth_user.role not in ('admin', 'superadmin') or not verify_password(auth_user.password, auth_password):
            return jsonify({'success': False, 'message': 'Invalid admin credentials'}), 403
    
    cart = session.get('cart', [])
    for item in cart:
        if item['product_id'] == product_id:
            item['quantity'] = quantity
            break
    
    session['cart'] = cart
    session.modified = True
    return jsonify({'success': True})

@app.route('/api/remove-from-cart/<int:product_id>', methods=['POST'])
@login_required
def remove_from_cart(product_id):
    # allow admin/superadmin to remove without extra auth; if current user is sales, require admin auth
    if session.get('role') == 'sales':
        data = request.get_json() or {}
        auth_username = data.get('auth_username')
        auth_password = data.get('auth_password')
        if not auth_username or not auth_password:
            return jsonify({'success': False, 'message': 'Admin credentials required to remove cart item'}), 401
        auth_user = User.query.filter_by(username=auth_username).first()
        if not auth_user or auth_user.role not in ('admin', 'superadmin') or not verify_password(auth_user.password, auth_password):
            return jsonify({'success': False, 'message': 'Invalid admin credentials'}), 403

    cart = session.get('cart', [])
    cart = [item for item in cart if item['product_id'] != product_id]
    session['cart'] = cart
    session.modified = True
    return jsonify({'success': True})

@app.route('/api/process-sale', methods=['POST'])
@login_required
def process_sale():
    cart = session.get('cart', [])
    if not cart:
        return jsonify({'success': False, 'message': 'Cart is empty'}), 400
    
    total_amount = 0
    total_items = 0
    
    # First, calculate totals by fetching product details
    for item in cart:
        product = Product.query.get(item['product_id'])
        if not product:
            return jsonify({'success': False, 'message': f'Product {item["product_id"]} not found'}), 400
        if product.stock < item['quantity']:
            return jsonify({'success': False, 'message': f'Insufficient stock for {product.name}'}), 400
        total_amount += item['quantity'] * product.price
        total_items += item['quantity']
    
    now = datetime.now()
    sale = Sale(
        user_id=session['user_id'], 
        cashier_username=session['username'],
        month=now.strftime('%B'),
        year=now.year,
        total_amount=total_amount, 
        total_items=total_items,
        sale_date=now
    )
    db.session.add(sale)
    db.session.flush()
    
    # Now process each cart item
    for item in cart:
        product = Product.query.get(item['product_id'])
        if product.stock < item['quantity']:
            db.session.rollback()
            return jsonify({'success': False, 'message': f'Insufficient stock for {product.name}'}), 400
        
        product.stock -= item['quantity']
        
        sale_item = SaleItem(sale_id=sale.id, product_id=item['product_id'], 
                           quantity=item['quantity'], price=product.price)
        db.session.add(sale_item)
        
        now = datetime.now()
        inventory = Inventory(
            product_id=item['product_id'],
            quantity_sold=item['quantity'],
            quantity_remaining=product.stock,
            month=now.strftime('%B'),
            year=now.year
        )
        db.session.add(inventory)
    
    db.session.commit()
    session['cart'] = []
    session.modified = True
    
    return jsonify({'success': True, 'sale_id': sale.id})

@app.route('/sales/receipt/<int:sale_id>')
@login_required
def receipt(sale_id):
    sale = Sale.query.get_or_404(sale_id)
    return render_template('receipt.html', sale=sale)

@app.route('/sales/history')
@login_required
def sales_history():
    user = User.query.get(session['user_id'])
    # Support optional ?date=YYYY-MM-DD (single-day view) or ?date=all to view all days.
    date_param = request.args.get('date')
    view_all = (date_param == 'all')

    # If no date provided, default to today (local date)
    if not date_param:
        # default to today view
        date_obj = datetime.now().date()
        date_param = date_obj.strftime('%Y-%m-%d')
        view_all = False

    # If asking for all dates, reuse previous grouping behavior
    if view_all:
        sales_q = Sale.query.order_by(Sale.sale_date.desc()).all()

        # Group sales by date (YYYY-MM-DD) for the UI.
        from collections import OrderedDict
        grouped = OrderedDict()
        for s in sales_q:
            day = s.sale_date.date()
            day_key = day.strftime('%Y-%m-%d')
            day_label = day.strftime('%B %d, %Y')
            if day_key not in grouped:
                grouped[day_key] = {'label': day_label, 'sales': []}
            grouped[day_key]['sales'].append(s)

        # Convert to a list sorted by day descending
        sales_by_date = []
        for k in sorted(grouped.keys(), reverse=True):
            sales_by_date.append((k, grouped[k]['label'], grouped[k]['sales']))

        return render_template('sales_history.html', sales_by_date=sales_by_date, view_all=True)

    # Single-date view: validate date_param
    try:
        selected_date = datetime.strptime(date_param, '%Y-%m-%d').date()
    except Exception:
        # invalid date -> fallback to today
        selected_date = datetime.now().date()
        date_param = selected_date.strftime('%Y-%m-%d')

    # Query sales that occurred on the selected date (server uses local dates for storage)
    sales_q = Sale.query.filter(func.date(Sale.sale_date) == date_param).order_by(Sale.sale_date.desc()).all()

    prev_date = (selected_date - timedelta(days=1)).strftime('%Y-%m-%d')
    next_date = (selected_date + timedelta(days=1)).strftime('%Y-%m-%d')
    today = datetime.now().date().strftime('%Y-%m-%d')

    return render_template('sales_history.html', sales=sales_q, date=date_param,
                           prev_date=prev_date, next_date=next_date, today=today, view_all=False)

# ==================== DATABASE INITIALIZATION ====================

def init_db():
    with app.app_context():
        db.create_all()
        # Run simple in-place migrations for SQLite: add missing columns if the table exists but schema is older.
        try:
            conn = db.engine.connect()
            # check for cashier_username in sale table
            cols = conn.execute(text("PRAGMA table_info('sale')")).fetchall()
            col_names = [c[1] for c in cols]
            if 'cashier_username' not in col_names:
                # SQLite supports ADD COLUMN for simple upgrades
                conn.execute(text("ALTER TABLE sale ADD COLUMN cashier_username VARCHAR(80) DEFAULT ''"))
                print('Added missing column: sale.cashier_username')
            # add month and year columns to sale if missing
            if 'month' not in col_names:
                conn.execute(text("ALTER TABLE sale ADD COLUMN month VARCHAR(20)"))
                print('Added missing column: sale.month')
            if 'year' not in col_names:
                conn.execute(text("ALTER TABLE sale ADD COLUMN year INTEGER"))
                print('Added missing column: sale.year')
            conn.close()
        except Exception as e:
            # non-fatal: if DB locked or other issue, surface for debugging but continue
            print('init_db: migration check failed:', e)

        # seed default superadmin if no users exist
        if User.query.count() == 0:
            superadmin = User(username='superadmin', password=generate_password_hash('superadmin123'), role='superadmin')
            db.session.add(superadmin)
            db.session.commit()
            print("Superadmin created: superadmin / superadmin123")

if __name__ == '__main__':
    init_db()
    app.run(debug=True)