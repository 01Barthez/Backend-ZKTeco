from datetime import datetime, timedelta, timezone
from flask import current_app, jsonify
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    get_jwt,
    decode_token
)
from werkzeug.security import generate_password_hash, check_password_hash
from models.user import User, RefreshToken
from models import db
import logging

logger = logging.getLogger(__name__)

def generate_tokens(user):
    """
    Génère une paire de jetons d'accès et de rafraîchissement pour un utilisateur.
    
    Args:
        user: Instance du modèle User
        
    Returns:
        dict: Dictionnaire contenant les jetons et les métadonnées
    """
    # Création des claims personnalisés
    additional_claims = {
        'is_admin': user.is_admin,
        'email': user.email,
        'username': user.username
    }
    
    # Création des jetons
    access_token = create_access_token(
        identity=str(user.id),
        additional_claims=additional_claims,
        expires_delta=current_app.config['JWT_ACCESS_TOKEN_EXPIRES']
    )
    
    refresh_token = create_refresh_token(
        identity=str(user.id),
        additional_claims=additional_claims,
        expires_delta=current_app.config['JWT_REFRESH_TOKEN_EXPIRES']
    )
    
    # Mise à jour de la date de dernière connexion
    user.update_last_login()
    
    return {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': user.to_dict(),
        'token_type': 'bearer',
        'expires_in': int(current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds())
    }

def refresh_access_token(refresh_token):
    """
    Rafraîchit un jeton d'accès à partir d'un jeton de rafraîchissement valide.
    
    Args:
        refresh_token (str): Jeton de rafraîchissement JWT
        
    Returns:
        dict: Nouveau jeton d'accès et métadonnées
    """
    try:
        # Décoder le jeton pour obtenir l'identité
        decoded = decode_token(refresh_token)
        user_id = decoded['sub']
        
        # Vérifier si le jeton n'a pas été révoqué
        if RefreshToken.is_revoked(decoded['jti']):
            raise RevokedTokenError('Token has been revoked')
        
        # Récupérer l'utilisateur
        user = User.query.get(user_id)
        if not user or not user.is_active:
            raise UserNotFoundError('User not found or inactive')
        
        # Créer un nouveau jeton d'accès
        access_token = create_access_token(
            identity=str(user.id),
            additional_claims={
                'is_admin': user.is_admin,
                'email': user.email,
                'username': user.username
            }
        )
        
        return {
            'access_token': access_token,
            'token_type': 'bearer',
            'expires_in': int(current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds())
        }
        
    except Exception as e:
        logger.error(f'Error refreshing token: {str(e)}')
        raise

def revoke_token(jti, user_id, expires_at):
    """
    Révoque un jeton en l'ajoutant à la liste noire.
    
    Args:
        jti (str): Identifiant unique du jeton JWT
        user_id (str): ID de l'utilisateur
        expires_at (datetime): Date d'expiration du jeton
    """
    RefreshToken.revoke_token(jti, user_id, expires_at)

def cleanup_expired_tokens():
    """Nettoie les jetons expirés de la base de données."""
    RefreshToken.cleanup_expired_tokens()

class AuthenticationError(Exception):
    """Exception pour les erreurs d'authentification."""
    pass

class UserNotFoundError(AuthenticationError):
    """Exception levée lorsque l'utilisateur n'est pas trouvé."""
    pass

class InvalidCredentialsError(AuthenticationError):
    """Exception levée lorsque les identifiants sont invalides."""
    pass

class AccountInactiveError(AuthenticationError):
    """Exception levée lorsque le compte est inactif."""
    pass

class RevokedTokenError(Exception):
    """Exception levée lorsqu'un jeton révoqué est utilisé."""
    pass

class RateLimitExceededError(Exception):
    """Exception levée lorsque la limite de taux est dépassée."""
    def __init__(self, message="Trop de tentatives, veuillez réessayer plus tard", retry_after=None):
        self.message = message
        self.retry_after = retry_after
        super().__init__(self.message)


def check_password_strength(password):
    """
    Vérifie la robustesse d'un mot de passe.
    
    Args:
        password (str): Le mot de passe à vérifier
        
    Returns:
        bool: True si le mot de passe est suffisamment fort, False sinon
        
    Raises:
        ValueError: Si le mot de passe ne respecte pas les exigences de sécurité
    """
    if not password:
        raise ValueError("Le mot de passe ne peut pas être vide")
    
    # Vérification de la longueur minimale
    min_length = 8
    if len(password) < min_length:
        raise ValueError(f"Le mot de passe doit contenir au moins {min_length} caractères")
    
    # Vérification de la présence de chiffres
    if not any(char.isdigit() for char in password):
        raise ValueError("Le mot de passe doit contenir au moins un chiffre")
    
    # Vérification de la présence de lettres majuscules
    if not any(char.isupper() for char in password):
        raise ValueError("Le mot de passe doit contenir au moins une lettre majuscule")
    
    # Vérification de la présence de lettres minuscules
    if not any(char.islower() for char in password):
        raise ValueError("Le mot de passe doit contenir au moins une lettre minuscule")
    
    # Vérification de la présence de caractères spéciaux
    special_chars = "!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~"
    if not any(char in special_chars for char in password):
        raise ValueError("Le mot de passe doit contenir au moins un caractère spécial")
    
    return True


def log_security_event(event_type, description, ip_address, user_id=None, details=None):
    """
    Enregistre un événement de sécurité dans les journaux.
    
    Args:
        event_type (str): Type d'événement (ex: 'login_success', 'login_failed', 'password_change')
        description (str): Description de l'événement
        ip_address (str): Adresse IP de l'utilisateur
        user_id (int, optional): ID de l'utilisateur concerné
        details (dict, optional): Détails supplémentaires sur l'événement
    """
    from models.log import Log
    from models import db
    
    try:
        log_entry = Log(
            event_type=f"security.{event_type}",
            description=description,
            ip_address=ip_address,
            user_id=user_id,
            details=details or {}
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        # En cas d'échec de l'enregistrement, on loggue l'erreur mais on ne fait pas échouer l'opération en cours
        logger.error(f"Failed to log security event: {str(e)}", exc_info=True)
        db.session.rollback()
