from flask import render_template, flash, redirect, url_for, request
from app import app, db
from app.forms import LoginForm, RegistrationForm, TransactionForm, ResetPasswordRequestForm, ResetPasswordForm, DeleteForm
from flask_login import current_user, login_user, logout_user, login_required
from app.models import User, Transaction
from werkzeug.urls import url_parse

@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    form = TransactionForm()
    if form.validate_on_submit():
        transaction = Transaction(description=form.description.data, author=current_user, 
            timestamp=form.timestamp.data, amount=form.amount.data)
        db.session.add(transaction)
        db.session.commit()
        flash('Your transaction is now posted.')
        return redirect(url_for('index'))        
    page = request.args.get('page', 1, type=int)
    transactions = current_user.transaction_posts().paginate(page, app.config['TRANSACTIONS_PER_PAGE'], False)
    next_url = url_for('index', page=transactions.next_num) \
        if transactions.has_next else None
    prev_url = url_for('index', page=transactions.prev_num) \
        if transactions.has_prev else None
    return render_template("index.html", title='Home', form=form,
                           transactions=transactions.items, next_url=next_url, prev_url=prev_url)    
                           
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password.')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)    
    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('You are now a registered user, please login.')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('We have sent you an email with instructions to reset your password.')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html', title='Reset Password', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)