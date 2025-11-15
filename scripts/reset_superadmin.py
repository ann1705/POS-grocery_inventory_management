import os, sys
base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base)

from app import app, db, User, generate_password_hash

new_password = 'superadmin123'
with app.app_context():
    user = User.query.filter_by(username='superadmin').first()
    if not user:
        print('superadmin user not found')
    else:
        # force pbkdf2 so environment doesn't choose scrypt by default
        user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        db.session.commit()
        print('superadmin password updated (pbkdf2:sha256)')
