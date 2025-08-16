"""
Contrôleur d'authentification pour l'API RH/Pointage.
Gère l'inscription, la connexion, la déconnexion et la gestion des jetons JWT.
"""
from flask import Blueprint, request, current_app, g, jsonify
from flask_restx import Resource, Namespace, fields
from flask_jwt_extended import (
    jwt_required,
    get_jwt_identity,
    get_jwt,
    create_access_token,
    verify_jwt_in_request,
    get_jwt_request_location
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash
from datetime import datetime, timedelta
import logging
import time
from functools import wraps

# Import des modèles
from models.user import User, RefreshToken

# Import des services
from services.auth import (
    generate_tokens,
    refresh_access_token,
    revoke_token,
    cleanup_expired_tokens,
    AuthenticationError,
    UserNotFoundError,
    InvalidCredentialsError,
    AccountInactiveError,
    RevokedTokenError,
    RateLimitExceededError,
    check_password_strength,
    log_security_event
)

# Import des schémas
from schemas import (
    user_schema, user_create_schema,
    login_schema, refresh_token_schema,
    change_password_schema, password_reset_request_schema,
    password_reset_schema
)

# Utilitaires
from utils.validators import validate_request
from utils.api_response import api_response, success_response, error_response

# Création du namespace d'authentification
auth_ns = Namespace('auth', description='Opérations d\'authentification')

# Modèles pour la documentation Swagger
user_model = auth_ns.model('User', {
    'id': fields.Integer(readOnly=True, description='Identifiant unique'),
    'username': fields.String(required=True, description="Nom d'utilisateur"),
    'email': fields.String(required=True, description='Adresse email'),
    'is_admin': fields.Boolean(description='Droits administrateur')
})

auth_tokens_model = auth_ns.model('AuthTokens', {
    'access_token': fields.String(description='Jeton d\'accès'),
    'refresh_token': fields.String(description='Jeton de rafraîchissement'),
    'token_type': fields.String(description='Type de jeton (Bearer)'),
    'expires_in': fields.Integer(description='Durée de validité en secondes')
})

login_model = auth_ns.model('LoginCredentials', {
    'username': fields.String(required=True, description="Nom d'utilisateur ou email"),
    'password': fields.String(required=True, description='Mot de passe')
})

refresh_token_model = auth_ns.model('RefreshToken', {
    'refresh_token': fields.String(required=True, description='Jeton de rafraîchissement')
})
from utils.responses import (
    success_response,
    error_response,
    validation_error_response,
    too_many_requests_response
)

# Configuration du logger
logger = logging.getLogger(__name__)

def get_limiter_key():
    """Fonction pour générer une clé unique pour le rate limiting."""
    # Utilise l'adresse IP du client comme clé par défaut
    key = get_remote_address()
    
    # Si l'utilisateur est authentifié, utilise son ID comme clé
    try:
        if hasattr(g, 'user_id') and g.user_id:
            return f"user_{g.user_id}"
    except:
        pass
        
    return key

# Configuration du rate limiting
limiter = Limiter(
    key_func=get_limiter_key,
    app=current_app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Création du Blueprint
auth_bp = Blueprint('auth', __name__)

# Modèles supplémentaires pour la documentation
user_create_model = auth_ns.model('UserCreate', {
    'username': fields.String(required=True, description="Nom d'utilisateur"),
    'email': fields.String(required=True, description='Adresse email valide'),
    'password': fields.String(required=True, description='Mot de passe (min 8 caractères)')
})

# Enregistrement des routes dans le namespace
@auth_ns.route('/register')
class Register(Resource):
    @auth_ns.doc('register')
    @auth_ns.expect(user_create_model)
    @auth_ns.response(201, 'Utilisateur créé avec succès', auth_tokens_model)
    @auth_ns.response(400, 'Données invalides ou erreur de validation')
    @auth_ns.response(409, 'Email ou nom d\'utilisateur déjà utilisé')
    @auth_ns.response(429, 'Trop de requêtes')
    @limiter.limit("5 per minute")
    def post(self):
        """
        Enregistre un nouvel utilisateur.
        """
        try:
            data = request.get_json()
            
            # Validation des données avec le schéma Marshmallow
            try:
                validated_data = user_create_schema.load(data)
            except ValidationError as err:
                return error_response(err.messages, 400)
            
            # Vérification de la force du mot de passe
            if not check_password_strength(validated_data['password']):
                return error_response(
                    "Le mot de passe doit contenir au moins 8 caractères, une majuscule, une minuscule, un chiffre et un caractère spécial",
                    400
                )
            
            # Vérification de l'unicité de l'email et du nom d'utilisateur (insensible à la casse)
            if User.query.filter(User.email.ilike(validated_data['email'])).first():
                return error_response("Un utilisateur avec cet email existe déjà", 409)
                
            if User.query.filter(User.username.ilike(validated_data['username'])).first():
                return error_response("Ce nom d'utilisateur est déjà pris", 409)
            
            # Création de l'utilisateur
            user = User(
                username=validated_data['username'],
                email=validated_data['email']
            )
            user.set_password(validated_data['password'])
            
            db.session.add(user)
            db.session.commit()
            
            # Génération des jetons
            tokens = generate_tokens(user.id, user.is_admin)
            
            # Journalisation de l'événement
            log_security_event(
                'user_registered',
                f'Nouvel utilisateur enregistré: {user.username}',
                request.remote_addr,
                user_id=user.id
            )
            
            # Création de la réponse
            response = success_response(
                data=tokens,
                message='Utilisateur enregistré avec succès',
                status_code=201
            )
            
            # Ajout des en-têtes de sécurité
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            
            return response
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error: {str(e)}", exc_info=True)
            return error_response("Une erreur est survenue lors de l'enregistrement", 500)

@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.doc('login')
    @auth_ns.expect(login_model)
    @auth_ns.response(200, 'Connexion réussie', auth_tokens_model)
    @auth_ns.response(400, 'Données invalides')
    @auth_ns.response(401, 'Identifiants invalides')
    @auth_ns.response(403, 'Compte désactivé')
    @auth_ns.response(429, 'Trop de tentatives')
    @limiter.limit("5 per minute")
    def post(self):
        """
        Authentifie un utilisateur et renvoie des jetons d'accès.
        """
        try:
            # Validation des données d'entrée
            data = login_schema.load(request.get_json())
            
            # Ajouter un délai aléatoire pour contrer les attaques par force brute
            time.sleep(0.5 + (0.1 * (1 + hash(data.get('username', '')) % 10)))
            
            # Recherche de l'utilisateur (insensible à la casse pour l'email/username)
            user = User.query.filter(
                (User.email.ilike(data['username'])) | 
                (User.username.ilike(data['username']))
            ).first()
            
            if not user:
                log_security_event(
                    'login_failed',
                    f'Tentative de connexion échouée - Utilisateur inconnu: {data["username"]}',
                    request.remote_addr
                )
                raise InvalidCredentialsError("Identifiants invalides")
            
            # Vérification du mot de passe
            if not check_password_hash(user.password_hash, data['password']):
                log_security_event(
                    'login_failed',
                    f'Tentative de connexion échouée - Mot de passe incorrect pour: {user.username}',
                    request.remote_addr,
                    user_id=user.id
                )
                raise InvalidCredentialsError("Identifiants invalides")
            
            # Vérification du statut du compte
            if not user.is_active:
                log_security_event(
                    'login_blocked',
                    f'Tentative de connexion à un compte désactivé: {user.username}',
                    request.remote_addr,
                    user_id=user.id
                )
                raise AccountInactiveError("Ce compte est désactivé")
            
            # Génération des jetons
            tokens = generate_tokens(user.id, user.is_admin)
            
            # Journalisation de la connexion réussie
            log_security_event(
                'login_success',
                f'Connexion réussie pour: {user.username}',
                request.remote_addr,
                user_id=user.id
            )
            
            # Création de la réponse
            response = success_response(
                data=tokens,
                message='Connexion réussie'
            )
            
            # Configuration du cookie de rafraîchissement si activé
            if current_app.config.get('JWT_COOKIE_SECURE', False):
                response.set_cookie(
                    key='refresh_token',
                    value=tokens['refresh_token'],
                    httponly=True,
                    secure=True,
                    samesite='Strict',
                    path='/api/auth/refresh'
                )
            
            # Ajout des en-têtes de sécurité
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            
            return response
            
        except Exception as e:
            logger.error(f"Login error: {str(e)}", exc_info=True)
            
            if isinstance(e, (InvalidCredentialsError, AccountInactiveError)):
                return error_response(str(e), 401 if isinstance(e, InvalidCredentialsError) else 403)
                
            return error_response('Une erreur est survenue lors de la connexion', 500)

@auth_ns.route('/refresh')
class Refresh(Resource):
    @auth_ns.doc('refresh_token')
    @auth_ns.expect(refresh_token_model)
    @auth_ns.response(200, 'Jeton rafraîchi avec succès', auth_tokens_model)
    @auth_ns.response(400, 'Données invalides')
    @auth_ns.response(401, 'Jeton de rafraîchissement invalide ou expiré')
    @auth_ns.response(429, 'Trop de requêtes')
    @limiter.limit("10 per minute")
    def post(self):
        """
        Rafraîchit un jeton d'accès expiré avec un jeton de rafraîchissement valide.
        """
        try:
            # Récupération du jeton depuis le corps de la requête ou des cookies
            refresh_token = None
            if request.is_json:
                data = request.get_json()
                refresh_token = data.get('refresh_token')
            
            # Si pas dans le JSON, vérifier dans les cookies
            if not refresh_token and 'refresh_token' in request.cookies:
                refresh_token = request.cookies.get('refresh_token')
            
            if not refresh_token:
                return error_response("Jeton de rafraîchissement manquant", 400)
            
            # Validation du schéma
            try:
                refresh_token_schema.load({'refresh_token': refresh_token})
            except ValidationError as err:
                return error_response(err.messages, 400)
            
            # Tentative de rafraîchissement du jeton
            try:
                tokens = refresh_access_token(refresh_token)
                
                # Journalisation de l'événement
                log_security_event(
                    'token_refreshed',
                    'Jeton d\'accès rafraîchi avec succès',
                    request.remote_addr,
                    user_id=get_jwt_identity()
                )
                
                # Création de la réponse
                response = success_response(
                    data=tokens,
                    message='Jeton rafraîchi avec succès'
                )
                
                # Mise à jour du cookie de rafraîchissement si nécessaire
                if current_app.config.get('JWT_COOKIE_SECURE', False):
                    response.set_cookie(
                        key='refresh_token',
                        value=tokens['refresh_token'],
                        httponly=True,
                        secure=True,
                        samesite='Strict',
                        path='/api/auth/refresh'
                    )
                
                # Ajout des en-têtes de sécurité
                response.headers['X-Content-Type-Options'] = 'nosniff'
                response.headers['X-Frame-Options'] = 'DENY'
                response.headers['X-XSS-Protection'] = '1; mode=block'
                
                return response
                
            except RevokedTokenError:
                log_security_event(
                    'token_revoked',
                    'Tentative d\'utilisation d\'un jeton révoqué',
                    request.remote_addr
                )
                return error_response("Ce jeton a été révoqué", 401)
                
        except Exception as e:
            logger.error(f"Refresh token error: {str(e)}", exc_info=True)
            log_security_event(
                'refresh_error',
                f'Erreur lors du rafraîchissement du jeton: {str(e)}',
                request.remote_addr
            )
            return error_response("Impossible de rafraîchir le jeton d'accès", 401)

@auth_ns.route('/logout')
class Logout(Resource):
    @auth_ns.doc('logout')
    @auth_ns.response(200, 'Déconnexion réussie')
    @auth_ns.response(401, 'Non autorisé')
    @auth_ns.response(500, 'Erreur serveur')
    @jwt_required()
    @limiter.limit("10 per minute")
    def post(self):
        """
        Déconnecte l'utilisateur en révoquant le jeton d'accès actuel.
        """
        try:
            jti = get_jwt()['jti']
            user_id = get_jwt_identity()
            expires_at = datetime.utcnow() + current_app.config['JWT_ACCESS_TOKEN_EXPIRES']
            
            # Révoquer le jeton actuel
            revoke_token(jti, user_id, expires_at)
            
            # Journalisation de la déconnexion
            log_security_event(
                'user_logout',
                f'Utilisateur déconnecté avec succès (ID: {user_id})',
                request.remote_addr,
                user_id=user_id
            )
            
            # Créer la réponse
            response = success_response(message='Déconnexion réussie')
            
            # Supprimer le cookie de rafraîchissement s'il existe
            if 'refresh_token' in request.cookies:
                response.delete_cookie('refresh_token')
            
            # Ajouter des en-têtes de sécurité
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            
            return response
            
        except Exception as e:
            logger.error(f"Logout error: {str(e)}", exc_info=True)
            log_security_event(
                'logout_error',
                f'Erreur lors de la déconnexion: {str(e)}',
                request.remote_addr,
                user_id=user_id if 'user_id' in locals() else None
            )
            return error_response('Échec de la déconnexion', 500)

@auth_ns.route('/me')
class CurrentUser(Resource):
    @auth_ns.doc('get_current_user')
    @auth_ns.response(200, 'Succès', user_model)
    @auth_ns.response(401, 'Non autorisé')
    @auth_ns.response(404, 'Utilisateur non trouvé')
    @auth_ns.response(500, 'Erreur serveur')
    @jwt_required()
    @limiter.limit("60 per minute")
    def get(self):
        """
        Récupère les informations de l'utilisateur actuellement authentifié.
        """
        try:
            current_user_id = get_jwt_identity()
            user = User.query.get(current_user_id)
            
            if not user:
                log_security_event(
                    'user_not_found',
                    f'Tentative d\'accès à un utilisateur introuvable (ID: {current_user_id})',
                    request.remote_addr,
                    user_id=current_user_id
                )
                return error_response('Utilisateur non trouvé', 404)
            
            # Vérifier si l'utilisateur est actif
            if not user.is_active:
                log_security_event(
                    'inactive_user_access',
                    f'Tentative d\'accès à un compte inactif (ID: {current_user_id})',
                    request.remote_addr,
                    user_id=current_user_id
                )
                return error_response('Ce compte est désactivé', 403)
            
            # Journaliser l'accès aux informations utilisateur
            log_security_event(
                'user_info_accessed',
                f'Informations utilisateur consultées (ID: {current_user_id})',
                request.remote_addr,
                user_id=current_user_id
            )
            
            # Créer la réponse
            response = success_response(
                data=user_schema.dump(user),
                message='Informations utilisateur récupérées avec succès'
            )
            
            # Ajouter des en-têtes de sécurité
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            
            return response
            
        except Exception as e:
            logger.error(f"Failed to get current user: {str(e)}", exc_info=True)
            log_security_event(
                'user_info_error',
                f'Erreur lors de la récupération des informations utilisateur: {str(e)}',
                request.remote_addr,
                user_id=current_user_id if 'current_user_id' in locals() else None
            )
            return error_response('Échec de la récupération des informations utilisateur', 500)

@auth_bp.route('/register', methods=['POST'])
@limiter.limit("5 per minute")  # Limite à 5 tentatives par minute
@validate_request(schema=user_create_schema)
def register():
    """
    Enregistre un nouvel utilisateur.
    
    ---
    tags:
      - Authentication
    description: Crée un nouveau compte utilisateur avec les informations fournies.
    requestBody:
      required: true
      content:
        application/json:
          schema: UserCreateSchema
    responses:
      201:
        description: Utilisateur enregistré avec succès
        content:
          application/json:
            schema:
              type: object
              properties:
                status:
                  type: string
                  example: success
                data:
                  $ref: '#/components/schemas/AuthTokens'
                message:
                  type: string
                  example: User registered successfully
      400:
        description: Données invalides ou erreur de validation
      409:
        description: Email ou nom d'utilisateur déjà utilisé
      429:
        description: Trop de requêtes
      500:
        description: Erreur serveur
    security: []
    """
    try:
        data = request.get_json()
        
        # Vérifier si l'utilisateur existe déjà
        if User.query.filter(func.lower(User.email) == data['email'].lower()).first():
            log_security_event(
                'register_duplicate_email',
                f'Tentative d\'enregistrement avec un email existant: {data["email"]}',
                request.remote_addr
            )
            return error_response('Email already registered', 409)
            
        if User.query.filter(func.lower(User.username) == data['username'].lower()).first():
            log_security_event(
                'register_duplicate_username',
                f'Tentative d\'enregistrement avec un nom d\'utilisateur existant: {data["username"]}',
                request.remote_addr
            )
            return error_response('Username already taken', 409)
        
        # Vérifier la force du mot de passe
        if not check_password_strength(data['password']):
            return error_response(
                'Password does not meet security requirements',
                400,
                details={
                    'requirements': {
                        'min_length': 8,
                        'require_uppercase': True,
                        'require_lowercase': True,
                        'require_digit': True,
                        'require_special': True
                    }
                }
            )
        
        # Créer un nouvel utilisateur
        user = User(
            email=data['email'].lower().strip(),
            username=data['username'].strip(),
            first_name=data.get('first_name', '').strip(),
            last_name=data.get('last_name', '').strip(),
            is_active=True,
            is_admin=data.get('is_admin', False),
            last_login_at=datetime.utcnow(),
            last_login_ip=request.remote_addr
        )
        user.set_password(data['password'])
        
        # Enregistrer l'utilisateur
        db.session.add(user)
        db.session.commit()
        
        # Générer les jetons
        tokens = generate_tokens(user)
        
        # Journaliser l'événement
        log_security_event(
            'user_registered',
            f'Nouvel utilisateur enregistré: {user.email} (ID: {user.id})',
            request.remote_addr,
            user_id=user.id
        )
        
        # En-têtes de sécurité
        response = success_response(
            data=tokens,
            message='User registered successfully',
            status_code=201
        )
        
        # Ajouter des en-têtes de sécurité
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        return response
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration error: {str(e)}", exc_info=True)
        log_security_event(
            'registration_error',
            f'Erreur lors de l\'enregistrement: {str(e)}',
            request.remote_addr
        )
        return error_response('Registration failed', 500)

@auth_bp.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Limite à 5 tentatives par minute
@validate_request(schema=login_schema)
def login():
    """
    Authentifie un utilisateur et renvoie des jetons d'accès.
    
    ---
    tags:
      - Authentication
    description: Authentifie un utilisateur avec un email/nom d'utilisateur et un mot de passe.
    requestBody:
      required: true
      content:
        application/json:
          schema: LoginSchema
    responses:
      200:
        description: Connexion réussie
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/AuthTokens'
      400:
        description: Données invalides ou erreur de validation
      401:
        description: Identifiants invalides
      403:
        description: Compte désactivé
      429:
        description: Trop de tentatives de connexion
      500:
        description: Erreur serveur
    security: []
    """
    try:
        data = request.get_json()
        identifier = data.get('identifier', '').strip()
        password = data.get('password')
        
        # Rechercher l'utilisateur par email ou nom d'utilisateur (insensible à la casse)
        user = User.query.filter(
            db.or_(
                db.func.lower(User.email) == identifier.lower(),
                db.func.lower(User.username) == identifier.lower()
            )
        ).first()
        
        # Vérifier les identifiants
        if not user or not user.check_password(password):
            # Journaliser la tentative échouée
            log_security_event(
                'login_failed',
                f'Tentative de connexion échouée pour l\'identifiant: {identifier}',
                request.remote_addr,
                user_id=user.id if user else None
            )
            
            # Délai aléatoire pour contrer les attaques par force brute
            time.sleep(1 + (hash(identifier) % 10) / 10)  # Entre 1 et 2 secondes
            
            return error_response('Invalid credentials', 401)
            
        # Vérifier si le compte est actif
        if not user.is_active:
            log_security_event(
                'login_inactive',
                f'Tentative de connexion à un compte inactif: {user.email}',
                request.remote_addr,
                user_id=user.id
            )
            return error_response('Account is inactive', 403)
        
        # Mettre à jour les informations de connexion
        user.last_login_at = datetime.utcnow()
        user.last_login_ip = request.remote_addr
        user.failed_login_attempts = 0  # Réinitialiser le compteur d'échecs
        db.session.commit()
        
        # Générer les jetons
        tokens = generate_tokens(user)
        
        # Journaliser la connexion réussie
        log_security_event(
            'login_success',
            f'Connexion réussie pour l\'utilisateur: {user.email}',
            request.remote_addr,
            user_id=user.id
        )
        
        # Créer la réponse
        response = success_response(
            data=tokens,
            message='Login successful'
        )
        
        # Ajouter des en-têtes de sécurité
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Définir un cookie HttpOnly pour le rafraîchissement du token
        if current_app.config.get('JWT_COOKIE_SECURE', False):
            response.set_cookie(
                key='refresh_token',
                value=tokens['refresh_token'],
                httponly=True,
                secure=True,
                samesite='Strict',
                max_age=int(current_app.config['JWT_REFRESH_TOKEN_EXPIRES'].total_seconds())
            )
        
        return response
        
    except RateLimitExceededError:
        log_security_event(
            'rate_limit_exceeded',
            f'Tentative de connexion bloquée par le rate limiting pour l\'IP: {request.remote_addr}',
            request.remote_addr
        )
        return too_many_requests_response()
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}", exc_info=True)
        log_security_event(
            'login_error',
            f'Erreur lors de la tentative de connexion: {str(e)}',
            request.remote_addr
        )
        return error_response('Login failed', 500)

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
@limiter.limit("10 per minute")  # Limite le rafraîchissement à 10 requêtes par minute
@validate_request(schema=refresh_token_schema)
def refresh():
    """
    Rafraîchit un jeton d'accès expiré à l'aide d'un jeton de rafraîchissement valide.
    
    ---
    tags:
      - Authentication
    description: Rafraîchit un jeton d'accès expiré avec un jeton de rafraîchissement valide.
    security:
      - JWT: []
    requestBody:
      required: true
      content:
        application/json:
          schema: RefreshTokenSchema
    responses:
      200:
        description: Jeton d'accès rafraîchi avec succès
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/AccessToken'
      400:
        description: Données invalides ou erreur de validation
      401:
        description: Jeton de rafraîchissement invalide ou expiré
      403:
        description: Accès refusé
      429:
        description: Trop de requêtes
      500:
        description: Erreur serveur
    """
    try:
        # Le jeton d'actualisation est déjà vérifié par le décorateur @jwt_required(refresh=True)
        current_user_id = get_jwt_identity()
        jti = get_jwt()['jti']
        
        # Vérifier si le token a été révoqué
        if RefreshToken.is_revoked(jti):
            log_security_event(
                'refresh_revoked_token',
                f'Tentative d\'utilisation d\'un jeton de rafraîchissement révoqué (JTI: {jti})',
                request.remote_addr,
                user_id=current_user_id
            )
            return error_response('Token has been revoked', 401)
        
        user = User.query.get(current_user_id)
        
        if not user or not user.is_active:
            log_security_event(
                'refresh_inactive_user',
                f'Tentative de rafraîchissement pour un utilisateur inactif ou introuvable (ID: {current_user_id})',
                request.remote_addr,
                user_id=current_user_id
            )
            return error_response('User not found or inactive', 401)
        
        # Créer un nouveau jeton d'accès
        access_token = create_access_token(identity=current_user_id)
        
        # Journaliser le rafraîchissement du token
        log_security_event(
            'token_refreshed',
            f'Nouveau jeton d\'accès généré pour l\'utilisateur ID: {current_user_id}',
            request.remote_addr,
            user_id=current_user_id
        )
        
        # Créer la réponse
        response = success_response({
            'access_token': access_token,
            'token_type': 'bearer',
            'expires_in': int(current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds())
        })
        
        # Ajouter des en-têtes de sécurité
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        return response
        
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}", exc_info=True)
        log_security_event(
            'refresh_token_error',
            f'Erreur lors du rafraîchissement du jeton: {str(e)}',
            request.remote_addr,
            user_id=current_user_id if 'current_user_id' in locals() else None
        )
        return error_response('Failed to refresh token', 401)

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
@limiter.limit("10 per minute")  # Limite à 10 déconnexions par minute
def logout():
    """
    Déconnecte l'utilisateur en révoquant le jeton d'accès actuel.
    
    ---
    tags:
      - Authentication
    description: Déconnecte l'utilisateur en révoquant le jeton d'accès actuel.
    security:
      - JWT: []
    responses:
      200:
        description: Déconnexion réussie
        content:
          application/json:
            schema:
              type: object
              properties:
                status:
                  type: string
                  example: success
                message:
                  type: string
                  example: Successfully logged out
      401:
        description: Non autorisé - jeton invalide ou expiré
      429:
        description: Trop de requêtes
      500:
        description: Erreur serveur
    """
    try:
        jti = get_jwt()['jti']
        user_id = get_jwt_identity()
        expires_at = datetime.utcnow() + current_app.config['JWT_ACCESS_TOKEN_EXPIRES']
        
        # Révoquer le jeton actuel
        revoke_token(jti, user_id, expires_at)
        
        # Journaliser la déconnexion
        log_security_event(
            'user_logout',
            f'Utilisateur déconnecté avec succès (ID: {user_id})',
            request.remote_addr,
            user_id=user_id
        )
        
        # Créer la réponse
        response = success_response(message='Successfully logged out')
        
        # Supprimer le cookie de rafraîchissement s'il existe
        if 'refresh_token' in request.cookies:
            response.delete_cookie('refresh_token')
        
        # Ajouter des en-têtes de sécurité
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        return response
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}", exc_info=True)
        log_security_event(
            'logout_error',
            f'Erreur lors de la déconnexion: {str(e)}',
            request.remote_addr,
            user_id=user_id if 'user_id' in locals() else None
        )
        return error_response('Logout failed', 500)

@auth_bp.route('/me', methods=['GET'])
@jwt_required()
@limiter.limit("60 per minute")  # Limite à 60 requêtes par minute
def get_current_user():
    """
    Récupère les informations de l'utilisateur actuellement authentifié.
    
    ---
    tags:
      - Authentication
    description: Récupère les informations détaillées de l'utilisateur actuellement connecté.
    security:
      - JWT: []
    responses:
      200:
        description: Informations utilisateur récupérées avec succès
        content:
          application/json:
            schema:
              type: object
              properties:
                status:
                  type: string
                  example: success
                data:
                  $ref: '#/components/schemas/User'
                message:
                  type: string
                  example: User retrieved successfully
      401:
        description: Non autorisé - jeton invalide ou expiré
      404:
        description: Utilisateur non trouvé
      429:
        description: Trop de requêtes
      500:
        description: Erreur serveur
    """
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user:
            log_security_event(
                'user_not_found',
                f'Tentative d\'accès à un utilisateur introuvable (ID: {current_user_id})',
                request.remote_addr,
                user_id=current_user_id
            )
            return error_response('User not found', 404)
        
        # Vérifier si l'utilisateur est actif
        if not user.is_active:
            log_security_event(
                'inactive_user_access',
                f'Tentative d\'accès à un compte inactif (ID: {current_user_id})',
                request.remote_addr,
                user_id=current_user_id
            )
            return error_response('Account is inactive', 403)
        
        # Journaliser l'accès aux informations utilisateur
        log_security_event(
            'user_info_accessed',
            f'Informations utilisateur consultées (ID: {current_user_id})',
            request.remote_addr,
            user_id=current_user_id
        )
        
        # Créer la réponse
        response = success_response(
            data=user_schema.dump(user),
            message='User retrieved successfully'
        )
        
        # Ajouter des en-têtes de sécurité
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        return response
        
    except Exception as e:
        logger.error(f"Failed to get current user: {str(e)}", exc_info=True)
        log_security_event(
            'user_info_error',
            f'Erreur lors de la récupération des informations utilisateur: {str(e)}',
            request.remote_addr,
            user_id=current_user_id if 'current_user_id' in locals() else None
        )
        return error_response('Failed to retrieve user', 500)

def schedule_token_cleanup():
    """
    Planifie le nettoyage périodique des jetons expirés.
    """
    try:
        scheduler = BackgroundScheduler()
        
        # Vérifier si la tâche existe déjà
        if not scheduler.get_job('cleanup_expired_tokens'):
            scheduler.add_job(
                func=cleanup_expired_tokens,
                trigger='interval',
                hours=1,  # Exécuter toutes les heures
                id='cleanup_expired_tokens',
                name='Nettoyage des jetons expirés',
                replace_existing=True
            )
            
            # Démarrer le planificateur
            if not scheduler.running:
                scheduler.start()
                logger.info("Planificateur de nettoyage des jetons démarré")
                
    except Exception as e:
        logger.error(f"Erreur lors de la configuration du nettoyage des jetons: {str(e)}")
        raise

# Démarrer le nettoyage planifié au démarrage de l'application
schedule_token_cleanup()

# Fonction pour arrêter le nettoyage planifié (utile pour les tests)
def stop_token_cleanup():
    """Arrête le nettoyage planifié des jetons."""
    try:
        scheduler = BackgroundScheduler()
        if scheduler.running:
            scheduler.shutdown()
            logger.info("Planificateur de nettoyage des jetons arrêté")
    except Exception as e:
        logger.error(f"Erreur lors de l'arrêt du nettoyage des jetons: {str(e)}")
        raise
