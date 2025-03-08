from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp

class SearchForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=4, max=20, message='Username must be between 4 and 20 characters.'),
        Regexp('^[A-Za-z0-9_]+$', message='Username can only contain letters, numbers, and underscores.')
    ])
    submit = SubmitField('Search')