from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from forms import ChangePasswordForm, MessageForm
from models.message import Message
from flask_wtf import FlaskForm
from database import db
from markdown import markdown
from bleach import clean

TAGS = ['h1', 'h2', 'h3', 'code', 'p', 'div', 'sup', 'strong', 'em', 'ul', 'ol', 'li', 'a', 'img', 'hr', 'blockquote']
ATTRIBUTES = {'a': ['href', 'title'], 'img': ['alt', 'src']}

bp = Blueprint('user', __name__, url_prefix='/')

@bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = MessageForm()
    if form.validate_on_submit():
        new_message = Message(content=form.content.data, user_id=current_user.id)
        db.session.add(new_message)
        db.session.commit()
        flash('Message added successfully!', 'success')
        return redirect(url_for('user.profile'))

    messages = Message.query.filter_by(user_id=current_user.id).order_by(Message.timestamp.desc()).all()
    for message in messages:
        message.content = clean(markdown(message.content), tags=TAGS, attributes=ATTRIBUTES)

    return render_template('profile.html', form=form, messages=messages)

@bp.route('/delete_message/<int:message_id>', methods=['GET', 'POST'])
@login_required
def delete_message(message_id):
    message = Message.query.get(message_id)
    message.content = clean(markdown(message.content), tags=TAGS, attributes=ATTRIBUTES)
    if not message or message.user_id != current_user.id:
        flash('You cannot delete this message.', 'danger')
        return redirect(url_for('user.profile'))

    form = FlaskForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            try:
                db.session.delete(message)
                db.session.commit()
                flash('Message deleted successfully!', 'success')
                return redirect(url_for('user.profile'))
            except Exception as e:
                flash(f'Failed to delete message. Error: {e}', 'danger')
                return redirect(url_for('user.profile'))

    return render_template('delete_message_confirm.html', message=message, form=form)

@bp.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.check_password(form.old_password.data):
            if form.old_password.data == form.new_password.data:
                flash('Provided new password is the same as the old one', 'danger')
                return redirect(url_for('user.change_password'))
            private_key = current_user.decrypt_RSA_private_key(form.old_password.data)
            current_user.encrypt_RSA_private_key(form.new_password.data, private_key)
            current_user.set_password(form.new_password.data)
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                flash('Failed to change password. Please try again later.', 'danger')
                return redirect(url_for('user.change_password'))
            flash('Password changed successfully!', 'success')
            return redirect(url_for('user.profile'))
        else:
            flash('Incorrect old password', 'danger')
    return render_template('change_password.html', form=form)
