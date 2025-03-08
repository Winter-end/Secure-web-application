from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from forms.message_form import MessageForm
from models.message import Message
from database import db
from bleach import clean
from markdown import markdown

TAGS = ['h1', 'h2', 'h3', 'code', 'p', 'div', 'sup', 'strong', 'em', 'ul', 'ol', 'li', 'a', 'img', 'hr', 'blockquote']
ATTRIBUTES = {'a': ['href', 'title'], 'img': ['alt', 'src']}

bp = Blueprint('message', __name__, url_prefix='/message')

@bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_message():
    form = MessageForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.password.data):
            flash('Invalid password', 'danger')
            return render_template('add_message.html', form=form)
        try:
            private_key = current_user.decrypt_RSA_private_key(form.password.data)
        except Exception as e:
            flash('Please check your password.', 'danger')
            return render_template('add_message.html', form=form)

        content = clean(markdown(form.content.data), tags=TAGS, attributes=ATTRIBUTES)
        is_public = form.is_public.data

        signature = Message.sign_message(private_key, content)

        new_message = Message(user_id=current_user.id, content=content, is_public=is_public, signature=signature)
        try:
            db.session.add(new_message)
            db.session.commit()
            flash('Message added successfully!', 'success')
            return redirect(url_for('user.profile'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to add message. Please try again later.', 'danger')
            return render_template('add_message.html', form=form)
    return render_template('add_message.html', form=form)

@bp.route('/add_form', methods=['GET'])
@login_required
def add_message_form():
    form = MessageForm()
    return render_template('add_message.html', form=form)