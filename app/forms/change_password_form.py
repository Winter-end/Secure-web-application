from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo, Regexp

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField(
        'Old Password',
        validators=[
            InputRequired(message='Old password is required.')
        ]
    )
    new_password = PasswordField(
        'New Password',
        validators=[
            InputRequired(message='New password is required.'),
            Length(min=8, message='New password is too short.'),
            Regexp(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$',
                message='Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character.'
            )
        ]
    )
    confirm_new_password = PasswordField(
        'Confirm New Password',
        validators=[
            InputRequired(message='Confirm new password is required.'),
            EqualTo('new_password', message='Passwords must match.')
        ]
    )
    submit = SubmitField('Change Password')
    