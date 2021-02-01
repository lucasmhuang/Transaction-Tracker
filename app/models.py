from app import db, login, app
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from time import time
import jwt

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    transactions = db.relationship('Transaction', backref='author', lazy='dynamic')

    def transaction_posts(self):
        own = Transaction.query.filter_by(user_id=self.id)
        return own.order_by(Transaction.timestamp.desc())

    def __repr__(self):
        return '<User {}>'.format(self.username)    

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256').decode('utf-8')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(140))
    timestamp = db.Column(db.String(140))
    amount = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Transaction {}>'.format(self.description)

@login.user_loader
def load_user(id):
    return User.query.get(int(id))