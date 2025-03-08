from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Length, EqualTo, Regexp

class RegistrationForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[
            InputRequired(message='Username is required.'),
            Length(min=4, max=20, message='Username must be between 4 and 20 characters.'),
            Regexp('^[A-Za-z0-9_]+$', message='Username can only contain letters, numbers, and underscores.')
        ]
    )
    password = PasswordField(
        'Password',
        validators=[
            InputRequired(message='Password is required.'),
            Length(min=8, message='Password is too short.'), # czy podanie informacji o minlnej długości hasła jest szkodliwe
            Regexp(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$',
                message='Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character.'
            )
        ]
    )
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            InputRequired(message='Confirm password is required.'),
            EqualTo('password', message='Passwords must match.')
        ]
    )