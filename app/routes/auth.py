from flask import Blueprint, render_template, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from forms import RegistrationForm, LoginForm, TwoFactorForm
from models import user as user_model
from database import db
from datetime import datetime, timedelta
from sqlalchemy.exc import IntegrityError
import base64
from io import BytesIO

MAX_LOGIN_ATTEMPTS = 5
LOGIN_DELAY_SECONDS = 10
OTP_INPUT_DELAY = 2

bp = Blueprint('auth', __name__, url_prefix='/')

@bp.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        existing_user = user_model.User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists.', 'danger')
            return render_template('register.html', form=form)

        try:
            new_user = user_model.User(username=username)
            new_user.set_password(password)
            new_user.generate_otp_secret()
            new_user.generate_RSA_keys(password)
            db.session.add(new_user)
            db.session.commit()
            db.session.refresh(new_user)

            img = new_user.generate_qr_code()
            buffered = BytesIO()
            img.save(buffered, format="PNG")
            img_str = base64.b64encode(buffered.getvalue()).decode()
            session['qr_code'] = img_str
            session['temp_user_id'] = new_user.id

            return redirect(url_for('auth.verify_registration'))

        except IntegrityError as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            return render_template('register.html', form=form)

        except Exception as e:
            db.session.rollback()
            flash('An unexpected error occurred during registration. Please try again.', 'danger')
            return render_template('register.html', form=form)

    return render_template('register.html', form=form)

@bp.route('/verify_registration', methods=['GET', 'POST'])
def verify_registration():
    if 'temp_user_id' not in session:
        flash('Session expired. Please register again.', 'danger')
        return redirect(url_for('auth.register'))

    user_id = session['temp_user_id']
    user = user_model.User.query.filter_by(id=user_id).first()

    form = TwoFactorForm()
    if form.validate_on_submit():
        if 'last_otp_input' in session:
            last_otp_input = session.get('last_otp_input')
            last_otp_input = last_otp_input.replace(tzinfo=None)
            if datetime.utcnow() - last_otp_input < timedelta(seconds=OTP_INPUT_DELAY):
                flash('Please wait a moment before entering another OTP.', 'warning')
                return render_template('verify_registration.html', form=form, qr_code=session.get('qr_code'))
        
        otp = form.otp.data
        if user.verify_otp(otp):
            session.pop('temp_user_id', None)
            session.pop('last_otp_input', None)
            session.pop('qr_code', None)
            login_user(user)
            flash('Account created successfully and you are logged in!', 'success')
            return redirect(url_for('user.profile'))
        else:
            session['last_otp_input'] = datetime.utcnow()
            flash('Invalid OTP', 'danger')
            return render_template('verify_registration.html', form=form, qr_code=session.get('qr_code'))
    
    return render_template('verify_registration.html', form=form, qr_code=session.get('qr_code'))

@bp.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if 'login_attempts' in session:
            last_attempt_time = session.get('last_attempt_time')
            last_attempt_time = last_attempt_time.replace(tzinfo=None)
            if last_attempt_time:
                if datetime.now() - last_attempt_time < timedelta(seconds=LOGIN_DELAY_SECONDS):
                    flash('Too many failed login attempts. Please try again later.', 'danger')
                    return render_template('login.html', form=form)

            if session['login_attempts'] >= MAX_LOGIN_ATTEMPTS:
                flash('Too many failed login attempts. You are blocked.', 'danger')
                return render_template('login.html', form=form)
        username = form.username.data
        password = form.password.data

        user = user_model.User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session.pop('login_attempts', None)
            session.pop('last_attempt_time', None)
            session['user_id'] = user.id
            return redirect(url_for('auth.two_factor'))
        else:
            login_attempts = session.get('login_attempts', 0) + 1
            session['login_attempts'] = login_attempts

            session['last_attempt_time'] = datetime.now()

            if login_attempts >= MAX_LOGIN_ATTEMPTS:
                flash('Too many failed login attempts. Please try again later.', 'danger')
            else:
                flash('Invalid username or password', 'danger')

    return render_template('login.html', form=form)


@bp.route("/two_factor", methods=['GET', 'POST'])
def two_factor():
    if current_user.is_authenticated:
        return redirect(url_for('user.profile'))
    
    user_id = session.get('user_id')
    if not user_id:
        flash('Session expired. Please log in again.', 'danger')
        return redirect(url_for('auth.login'))
    
    user = user_model.User.query.filter_by(id=user_id).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('auth.login'))
    
    form = TwoFactorForm()
    if form.validate_on_submit():
        if 'last_otp_input' in session:
            last_otp_input = session.get('last_otp_input')
            last_otp_input = last_otp_input.replace(tzinfo=None)
            if datetime.utcnow() - last_otp_input < timedelta(seconds=OTP_INPUT_DELAY):
                flash('Please wait a moment before entering another OTP.', 'warning')
                return render_template('two_factor.html', form=form)
        
        otp = form.otp.data
        if user.verify_otp(otp):
            session.pop('last_otp_input', None)
            login_user(user)
            session.pop('user_id', None)
            return redirect(url_for('user.profile'))
        else:
            session['last_otp_input'] = datetime.utcnow()
            flash('Invalid OTP', 'danger')
        
    return render_template('two_factor.html', form=form)

@bp.route("/logout")
@login_required
def logout():
    logout_user()

    session.pop('user_id', None)
    return redirect(url_for('index.index'))
