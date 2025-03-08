from flask_login import UserMixin
from flask import current_app
from flask_bcrypt import Bcrypt
import pyotp
from datetime import datetime
from database import db
import qrcode

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

bcrypt = Bcrypt()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False, index=True)
    password = db.Column(db.String(256), nullable=False)
    encrypted_otp_secret = db.Column(db.LargeBinary, nullable=False)
    public_key = db.Column(db.String(4096), nullable=False, unique=True)
    encrypted_private_key = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    messages = db.relationship('Message', backref='user', lazy=True)

    def generate_RSA_keys(self, password):
        """
        Generate RSA keys and encrypt the private key using AES256 with the user's password.
        """
        key = RSA.generate(4096)
        public_key = key.publickey()

        public_pem = public_key.export_key().decode()
        private_key_bytes = key.export_key()
        private_key = RSA.import_key(private_key_bytes)

        self.public_key = public_pem
        User.encrypt_RSA_private_key(self, password, private_key)

    def encrypt_RSA_private_key(self, password, key):
        """
        Encrypt the private key using the user's password.
        """        
        salt = get_random_bytes(16)

        key_derived = PBKDF2(password.encode(), salt, count=10000, dkLen=32)

        private_key_bytes = key.export_key()

        iv = get_random_bytes(16)
        cipher = AES.new(key_derived, AES.MODE_CBC, iv=iv)
        ciphertext = cipher.encrypt(pad(private_key_bytes, AES.block_size))

        self.encrypted_private_key = salt + iv + ciphertext
        
    def decrypt_RSA_private_key(self, password):
        """
        Decrypt the private key using the user's password.
        """
        salt = self.encrypted_private_key[:16]
        iv = self.encrypted_private_key[16:32]
        ciphertext = self.encrypted_private_key[32:]

        key_derived = PBKDF2(password.encode(), salt, count=10000, dkLen=32)

        cipher = AES.new(key_derived, AES.MODE_CBC, iv=iv)
        private_key_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)

        private_key = RSA.import_key(private_key_bytes)

        return private_key
    
    def set_password(self, password):
        """Set the user's password to the hashed version of the provided password."""
        sha256_hash = SHA256.new(password.encode('utf-8')).digest()
        
        bcrypt_hash = bcrypt.generate_password_hash(sha256_hash, rounds=14).decode('utf-8')
        
        self.password = bcrypt_hash

    def check_password(self, password):
        """Check if the provided password matches the stored password hash."""
        sha256_hash = SHA256.new(password.encode('utf-8')).digest()
        
        return bcrypt.check_password_hash(self.password, sha256_hash)
    
    def generate_otp_secret(self):
        """Generate a random OTP secret."""
        otp_secret = pyotp.random_base32()
        User.encrypt_OTP_secret(self, otp_secret)

    def encrypt_OTP_secret(self, otp_secret):
        """
        Encrypt the private key using the password from the server.
        """        
        salt = get_random_bytes(16)

        password = current_app.config['OTP_SECRET_ENCRYPTION_PASSWORD']

        key_derived = PBKDF2(password.encode(), salt, count=10000, dkLen=32)

        iv = get_random_bytes(16)
        cipher = AES.new(key_derived, AES.MODE_CBC, iv=iv)
        ciphertext = cipher.encrypt(pad(otp_secret.encode(), AES.block_size))

        self.encrypted_otp_secret = salt + iv + ciphertext
        
    def decrypt_OTP_secret(self):
        """
        Decrypt the OTP secret using the password from the server.
        """
        password = current_app.config['OTP_SECRET_ENCRYPTION_PASSWORD']
        
        salt = self.encrypted_otp_secret[:16]
        iv = self.encrypted_otp_secret[16:32]
        ciphertext = self.encrypted_otp_secret[32:]

        key_derived = PBKDF2(password.encode(), salt, count=10000, dkLen=32)

        cipher = AES.new(key_derived, AES.MODE_CBC, iv=iv)
        decrypted_private_pem = unpad(cipher.decrypt(ciphertext), AES.block_size)

        return decrypted_private_pem.decode()

    def verify_otp(self, otp):
        """Verify the provided OTP."""
        otp_secret = self.decrypt_OTP_secret()
        totp = pyotp.TOTP(otp_secret)
        return totp.verify(otp)

    def update_last_login(self):
        """Update the last login timestamp."""
        self.last_login = datetime.utcnow()
        db.session.commit()

    def generate_qr_code(self):
        otp_secret = self.decrypt_OTP_secret()
        uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(
            name=self.username, issuer_name="MessagesApp"
        )
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        return img