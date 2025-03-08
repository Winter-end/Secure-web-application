from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length

class TwoFactorForm(FlaskForm):
    otp = StringField('OTP', validators=[
        DataRequired(), 
        Length(min=6, max=6, message='OTP must be 6 characters long.')])
    submit = SubmitField('Verify')