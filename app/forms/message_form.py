# forms/message_form.py
from flask_wtf import FlaskForm
from wtforms import TextAreaField, BooleanField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length

class MessageForm(FlaskForm):
    content = TextAreaField(
        'Message Content',
        validators=[
            DataRequired(message='Message content is required.'),
            Length(max=1000, message='Message content must be less than or 1000 characters.')
        ]
    )
    is_public = BooleanField('Make this message public')
    password = PasswordField(
        'Password to cofirm message posting',
        validators=[
            DataRequired(message='Password is required.')
        ]
    )
    submit = SubmitField('Add Message')