"""
Schémas de validation pour les utilisateurs et l'authentification.
"""
from marshmallow import Schema, fields, validate, validates, ValidationError, post_load
from datetime import datetime
import re


class BaseSchema(Schema):
    """Classe de base pour tous les schémas avec des méthodes utilitaires."""
    
    class Meta:
        ordered = True  # Pour maintenir l'ordre des champs


class UserSchema(BaseSchema):
    """Schéma pour la sérialisation/désérialisation des utilisateurs."""
    
    # Champs en lecture seule (retournés dans les réponses API)
    id = fields.Str(dump_only=True, description="Identifiant unique de l'utilisateur")
    created_at = fields.DateTime(dump_only=True, format='iso', 
                               description="Date de création du compte")
    updated_at = fields.DateTime(dump_only=True, format='iso',
                               description="Date de dernière mise à jour")
    last_login = fields.DateTime(dump_only=True, format='iso',
                               description="Date de dernière connexion")
    
    # Champs modifiables
    email = fields.Email(
        required=True,
        error_messages={"invalid": "Adresse email invalide"},
        description="Adresse email de l'utilisateur"
    )
    
    username = fields.Str(
        required=True,
        validate=validate.Length(
            min=3, 
            max=50,
            error="Le nom d'utilisateur doit contenir entre {min} et {max} caractères"
        ),
        description="Nom d'utilisateur unique"
    )
    
    password = fields.Str(
        load_only=True,
        required=False,
        validate=validate.Length(
            min=8,
            error="Le mot de passe doit contenir au moins {min} caractères"
        ),
        description="Mot de passe (uniquement pour la création/mise à jour)"
    )
    
    is_active = fields.Bool(
        load_default=True,
        description="Indique si le compte est actif"
    )
    
    is_admin = fields.Bool(
        load_default=False,
        description="Indique si l'utilisateur a des droits d'administrateur"
    )
    
    is_verified = fields.Bool(
        dump_only=True,
        description="Indique si l'email de l'utilisateur a été vérifié"
    )
    
    # Validations personnalisées
    @validates('username')
    def validate_username(self, value):
        """Valide le format du nom d'utilisateur."""
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', value):
            raise ValidationError(
                "Le nom d'utilisateur ne peut contenir que des lettres, "
                "chiffres, tirets, points et tirets bas"
            )
    
    @validates('password')
    def validate_password(self, value):
        """Valide la complexité du mot de passe."""
        if not any(char.isdigit() for char in value):
            raise ValidationError("Le mot de passe doit contenir au moins un chiffre")
        if not any(char.isupper() for char in value):
            raise ValidationError("Le mot de passe doit contenir au moins une majuscule")
        if not any(char.islower() for char in value):
            raise ValidationError("Le mot de passe doit contenir au moins une minuscule")
        if not any(char in "!@#$%^&*(),.?\":{}|<>" for char in value):
            raise ValidationError(
                "Le mot de passe doit contenir au moins un caractère spécial"
            )
    
    # Méthodes utilitaires
    @post_load
    def process_user(self, data, **kwargs):
        """Traitement après chargement des données."""
        # Nettoyage des chaînes de caractères
        if 'username' in data:
            data['username'] = data['username'].strip()
        if 'email' in data:
            data['email'] = data['email'].lower().strip()
        return data


class LoginSchema(BaseSchema):
    """Schéma pour la validation des identifiants de connexion."""
    
    identifier = fields.Str(
        required=True,
        description="Email ou nom d'utilisateur"
    )
    
    password = fields.Str(
        required=True,
        load_only=True,
        description="Mot de passe"
    )
    
    remember_me = fields.Bool(
        load_default=False,
        description="Rester connecté"
    )


class RefreshTokenSchema(BaseSchema):
    """Schéma pour la validation des jetons de rafraîchissement."""
    
    refresh_token = fields.Str(
        required=True,
        description="Jeton de rafraîchissement"
    )


class ChangePasswordSchema(BaseSchema):
    """Schéma pour le changement de mot de passe."""
    
    current_password = fields.Str(
        required=True,
        load_only=True,
        description="Mot de passe actuel"
    )
    
    new_password = fields.Str(
        required=True,
        load_only=True,
        validate=validate.Length(min=8),
        description="Nouveau mot de passe"
    )
    
    confirm_password = fields.Str(
        required=True,
        load_only=True,
        description="Confirmation du nouveau mot de passe"
    )
    
    @validates('confirm_password')
    def validate_confirm_password(self, value, **kwargs):
        """Vérifie que les mots de passe correspondent."""
        if 'new_password' in self.context and value != self.context['new_password']:
            raise ValidationError("Les mots de passe ne correspondent pas")


class PasswordResetRequestSchema(BaseSchema):
    """Schéma pour la demande de réinitialisation de mot de passe."""
    
    email = fields.Email(
        required=True,
        description="Adresse email du compte"
    )


class PasswordResetSchema(BaseSchema):
    """Schéma pour la réinitialisation du mot de passe."""
    
    token = fields.Str(
        required=True,
        description="Jeton de réinitialisation"
    )
    
    new_password = fields.Str(
        required=True,
        load_only=True,
        validate=validate.Length(min=8),
        description="Nouveau mot de passe"
    )
    
    confirm_password = fields.Str(
        required=True,
        load_only=True,
        description="Confirmation du nouveau mot de passe"
    )
    
    @validates('confirm_password')
    def validate_confirm_password(self, value, **kwargs):
        """Vérifie que les mots de passe correspondent."""
        if 'new_password' in self.context and value != self.context['new_password']:
            raise ValidationError("Les mots de passe ne correspondent pas")


class UserCreateSchema(UserSchema):
    """Schéma pour la création d'un nouvel utilisateur."""
    
    # Surcharge des champs requis pour la création
    password = fields.Str(
        required=True,
        load_only=True,
        validate=validate.Length(min=8),
        description="Mot de passe (au moins 8 caractères, avec majuscule, minuscule, chiffre et caractère spécial)"
    )
    
    # Champs spécifiques à la création
    confirm_password = fields.Str(
        required=True,
        load_only=True,
        description="Confirmation du mot de passe"
    )
    
    # Référence au schéma de base pour l'héritage
    class Meta(UserSchema.Meta):
        pass
    
    # Validation personnalisée pour la confirmation du mot de passe
    @validates('confirm_password')
    def validate_confirm_password(self, value, **kwargs):
        """Vérifie que les mots de passe correspondent."""
        if 'password' in self.context.get('data', {}) and value != self.context['data']['password']:
            raise ValidationError("Les mots de passe ne correspondent pas")


# Instances des schémas pour une utilisation facile
user_schema = UserSchema()
user_list_schema = UserSchema(many=True)
user_create_schema = UserCreateSchema()
login_schema = LoginSchema()
refresh_token_schema = RefreshTokenSchema()
change_password_schema = ChangePasswordSchema()
password_reset_request_schema = PasswordResetRequestSchema()
password_reset_schema = PasswordResetSchema()
