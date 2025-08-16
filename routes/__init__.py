from .auth_routes import auth_bp
from .employee_routes import employee_bp
from .log_routes import log_bp
from .report_routes import report_bp
from .department_routes import department_bp

__all__ = ['employee_bp', 'log_bp', 'report_bp', 'auth_bp', 'department_bp']

# Les blueprints seront automatiquement découverts par l'application principale
# via app.register_blueprint() dans create_app()']
