from datetime import datetime, timezone
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import get_jwt_identity
import uuid

class User(db.Model):
    """
    Modèle utilisateur pour l'authentification et l'autorisation.
    """
    __tablename__ = 'users'

    # Identifiants
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    
    # Rôles et permissions
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    
    # Métadonnées
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Relations
    refresh_tokens = db.relationship('RefreshToken', back_populates='user', cascade='all, delete-orphan')
    
    # Méthodes de sécurité
    def set_password(self, password):
        """
        Hash et définit le mot de passe de l'utilisateur.
        """
        if not password or len(password) < 8:
            raise ValueError("Le mot de passe doit contenir au moins 8 caractères")
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password):
        """
        Vérifie si le mot de passe fourni correspond au hash stocké.
        """
        return check_password_hash(self.password_hash, password)
    
    def update_last_login(self):
        """
        Met à jour la date de dernière connexion de l'utilisateur.
        """
        self.last_login = datetime.utcnow()
        db.session.commit()
    
    def has_role(self, role_name):
        """
        Vérifie si l'utilisateur a un rôle spécifique.
        """
        # Pour une implémentation simple, on utilise is_admin comme rôle
        # Dans une application plus complexe, vous pourriez avoir une table de rôles séparée
        if role_name == 'admin':
            return self.is_admin
        return False
    
    @classmethod
    def get_current_user(cls):
        """
        Récupère l'utilisateur actuellement authentifié.
        """
        from flask_jwt_extended import get_jwt_identity
        
        user_id = get_jwt_identity()
        if not user_id:
            return None
            
        return cls.query.get(user_id)
    
    def to_dict(self):
        """
        Convertit l'utilisateur en dictionnaire pour la sérialisation JSON.
        """
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'is_admin': self.is_admin,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }
    
    def __repr__(self):
        return f'<User {self.username} ({self.email})>'


class RefreshToken(db.Model):
    """
    Modèle pour stocker les jetons de rafraîchissement révoqués.
    """
    __tablename__ = 'refresh_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    user = db.relationship('User', back_populates='refresh_tokens')
    
    @classmethod
    def is_revoked(cls, jti):
        """Vérifie si un jeton a été révoqué."""
        return cls.query.filter_by(jti=jti).first() is not None
    
    @classmethod
    def revoke_token(cls, jti, user_id, expires_at):
        """Marque un jeton comme révoqué."""
        revoked_token = cls(jti=jti, user_id=user_id, expires_at=expires_at)
        db.session.add(revoked_token)
        db.session.commit()
    
    @classmethod
    def cleanup_expired_tokens(cls):
        """Supprime les jetons expirés de la base de données."""
        cls.query.filter(cls.expires_at < datetime.utcnow()).delete()
        db.session.commit()
