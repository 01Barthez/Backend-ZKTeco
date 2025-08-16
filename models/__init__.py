from flask_sqlalchemy import SQLAlchemy

# Instance SQLAlchemy
db = SQLAlchemy()

# Base pour tous les modèles
Base = db.Model

# Importer tous les modèles ici pour que SQLAlchemy les connaisse
from .user import User, RefreshToken
from .employee import Employee
from .department import Department
from .log import Log

# Exposer ce qui doit être accessible depuis l'extérieur
__all__ = ['db', 'Base', 'User', 'Employee', 'Department', 'Log', 'RefreshToken']
