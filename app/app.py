from flask import Flask
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from config import Config
from routes import index, user, message, auth
from database import db
from models import user as user_model

app = Flask(__name__)
app.config.from_object(Config)

bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'auth.login'

from models import user as user_model

@login_manager.user_loader
def load_user(user_id):
    return user_model.User.query.get(int(user_id))

app.register_blueprint(index.bp)
app.register_blueprint(user.bp)
app.register_blueprint(message.bp)
app.register_blueprint(auth.bp)

@app.cli.command("init-db")
def init_db():
    """Initialize the database."""
    with app.app_context():
        db.create_all()
        print("Database initialized.")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        db.session.commit()
    app.run(host='0.0.0.0', port=5000)
