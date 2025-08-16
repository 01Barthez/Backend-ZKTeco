import traceback
from flask import Flask, jsonify, redirect, url_for
from flask_cors import CORS
from config import Config
from models import db
from routes import employee_bp, log_bp, report_bp, auth_bp
from routes.auth_routes import auth_ns  # Import du namespace d'authentification
from flask_jwt_extended import JWTManager
from swagger_docs import init_swagger, api


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
    app.register_blueprint(auth_bp, url_prefix='/api')
    app.register_blueprint(employee_bp, url_prefix='/api')
    app.register_blueprint(log_bp, url_prefix='/api')
    app.register_blueprint(report_bp, url_prefix='/api')
    
    # Initialisation de la documentation Swagger
    init_swagger(app)
    
    # Redirection de la racine vers la documentation
    @app.route('/')
    def index():
        return redirect(url_for('swagger.docs'))
    
    # Configuration CORS
    @app.after_request
    def after_request(response):
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
        response.headers.add('X-Content-Type-Options', 'nosniff')
        response.headers.add('X-Frame-Options', 'DENY')
        response.headers.add('X-XSS-Protection', '1; mode=block')
        return response

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
