import base64
from database import db
from datetime import datetime
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

class Message(db.Model):
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_public = db.Column(db.Boolean, default=True)
    signature = db.Column(db.Text, nullable=True, unique=True)
    
    def sign_message(private_key, message):
        message_hash = SHA256.new(message.encode())
        signature = pkcs1_15.new(private_key).sign(message_hash)
        return base64.b64encode(signature).decode('utf-8')