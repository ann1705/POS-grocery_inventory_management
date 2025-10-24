from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    username = 'sales1'
    if not User.query.filter_by(username=username).first():
        user = User(username=username, password=generate_password_hash('sales123'), role='sales')
        db.session.add(user)
        db.session.commit()
        print('Created sales user:', username, 'password: sales123')
    else:
        print('Sales user already exists')
