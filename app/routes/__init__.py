from .index import bp as index_bp
from .user import bp as user_bp
from .message import bp as message_bp
from .auth import bp as auth_bp

bp = index_bp
bp.register_blueprint(user_bp)
bp.register_blueprint(message_bp)
bp.register_blueprint(auth_bp)