from flask import Blueprint, render_template, flash, redirect, url_for
from models.message import Message
from markdown import markdown
from models.user import User
from bleach import clean
from forms import SearchForm

bp = Blueprint('index', __name__, url_prefix='/')

TAGS = ['h1', 'h2', 'h3', 'code', 'p', 'div', 'sup', 'strong', 'em', 'ul', 'ol', 'li', 'a', 'img', 'hr', 'blockquote']
ATTRIBUTES = {'a': ['href', 'title'], 'img': ['alt', 'src']}

@bp.route("/", methods=['GET', 'POST'])
def index():
    form = SearchForm()
    if form.validate_on_submit():
        username = form.username.data
        return redirect(url_for('index.public_profile', username=username))
    return render_template('index.html', form=form)

@bp.route('/public_profile/<username>', methods=['GET'])
def public_profile(username):
    user = User.query.filter_by(username=username).first()
    if user:
        messages = Message.query.filter_by(user_id=user.id).order_by(Message.timestamp.desc()).all()
        public_messages = [message for message in messages if message.is_public]
        
        for message in public_messages:
            message.content = clean(markdown(message.content), tags=TAGS, attributes=ATTRIBUTES)

        return render_template('user_messages.html', user=user, messages=public_messages)
    else:
        flash('User not found!', 'danger')
        return redirect(url_for('index.index'))