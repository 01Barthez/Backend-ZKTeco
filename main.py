import traceback
from flask import Flask, jsonify
from flask_cors import CORS
from config import Config
from models import db
from routes import employee_bp, log_bp, report_bp, auth_bp
from flask_jwt_extended import JWTManager


def create_app():
    """Factory pour créer et configurer l'application Flask"""
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialisation extensions
    db.init_app(app)
    JWTManager(app)
    CORS(app)

    # Gestionnaire global d'erreurs
    @app.errorhandler(Exception)
    def handle_all_exceptions(e):
        app.logger.error(f"Exception: {e}")
        traceback.print_exc()
        return jsonify({
            "msg": str(e),
            "trace": traceback.format_exc()
        }), 500

    # Enregistrement des Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(employee_bp)
    app.register_blueprint(log_bp)
    app.register_blueprint(report_bp)

    return app


def init_database(app):
    """Création des tables et d'un utilisateur admin par défaut"""
    with app.app_context():
        db.create_all()
        from models.user import User

        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', is_admin=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            app.logger.info("✅ Admin créé avec succès !")
        else:
            app.logger.info("ℹ️ Admin déjà existant.")


if __name__ == '__main__':
    application = create_app()
    init_database(application)
    application.run(debug=True, host="0.0.0.0", port=5000)
