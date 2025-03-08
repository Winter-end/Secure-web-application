import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    OTP_SECRET_ENCRYPTION_PASSWORD = os.environ.get('OTP_SECRET_ENCRYPTION_PASSWORD')