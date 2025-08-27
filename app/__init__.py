import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from .config import Config
from sqlalchemy import inspect
from flask_mail import Mail

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message_category = 'info'
mail = Mail()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    mail.init_app(app)
    from app.models import User, TracerouteHistory
    with app.app_context():
        inspector = inspect(db.engine)
        if not inspector.has_table('user'):
            db.create_all()
            print("Database tables created.")
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    from app.routes.auth import auth_bp
    from app.routes.main import main_bp
    from app.routes.profile import profile_bp
    from app.routes.tools import tools_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(tools_bp)

    @app.shell_context_processor
    def make_shell_context():
        return {'db': db, 'User': User, 'TracerouteHistory': TracerouteHistory}

    return app



