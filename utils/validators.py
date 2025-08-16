"""
Module pour la validation des requêtes et des données.
Fournit des décorateurs et des fonctions utilitaires pour valider les entrées.
"""
from functools import wraps
from flask import request, current_app
from marshmallow import ValidationError
from http import HTTPStatus
from typing import Callable, Any, Optional, Type, TypeVar, Dict, List, Union

from .responses import validation_error_response

T = TypeVar('T')

class validate_request:
    """
    Décorateur pour valider les données de la requête avec un schéma Marshmallow.
    
    Exemple d'utilisation:
        @auth_bp.route('/login', methods=['POST'])
        @validate_request(schema=LoginSchema())
        def login():
            data = request.get_json()
            # Les données sont déjà validées ici
            ...
    """
    
    def __init__(self, schema=None, location='json', **kwargs):
        """
        Initialise le validateur avec un schéma et des options.
        
        Args:
            schema: Instance d'un schéma Marshmallow pour la validation
            location: Emplacement des données ('json', 'form', 'args', etc.)
            **kwargs: Options supplémentaires pour le schéma
        """
        self.schema = schema
        self.location = location
        self.schema_kwargs = kwargs
    
    def __call__(self, f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not self.schema:
                return f(*args, **kwargs)
                
            try:
                # Récupérer les données en fonction de l'emplacement
                if self.location == 'json':
                    data = request.get_json() or {}
                elif self.location == 'form':
                    data = request.form.to_dict()
                elif self.location == 'args':
                    data = request.args.to_dict()
                else:
                    data = {}
                
                # Valider les données avec le schéma
                validated_data = self.schema.load(data, **self.schema_kwargs)
                
                # Ajouter les données validées à request.validated_data
                if not hasattr(request, 'validated_data'):
                    request.validated_data = {}
                request.validated_data.update(validated_data)
                
                return f(*args, **kwargs)
                
            except ValidationError as err:
                current_app.logger.warning(f"Validation error: {err.messages}")
                return validation_error_response(errors=err.messages)
                
            except Exception as e:
                current_app.logger.error(f"Validation error: {str(e)}")
                return validation_error_response("Invalid request data")
                
        return decorated_function


def validate_data(schema, data: Any, **kwargs) -> tuple:
    """
    Valide des données avec un schéma Marshmallow.
    
    Args:
        schema: Schéma Marshmallow ou classe de schéma
        data: Données à valider
        **kwargs: Arguments supplémentaires pour schema.load()
        
    Returns:
        Tuple (données_validées, erreurs)
    """
    try:
        if isinstance(schema, type):
            schema = schema()
        validated_data = schema.load(data, **kwargs)
        return validated_data, None
    except ValidationError as err:
        return None, err.messages


def validate_email(email: str) -> bool:
    """
    Valide une adresse email.
    
    Args:
        email: Adresse email à valider
        
    Returns:
        bool: True si l'email est valide, False sinon
    """
    import re
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return bool(re.match(email_regex, email))


def validate_password(password: str, min_length: int = 8) -> tuple[bool, list[str]]:
    """
    Valide un mot de passe selon des critères de complexité.
    
    Args:
        password: Mot de passe à valider
        min_length: Longueur minimale requise
        
    Returns:
        Tuple (est_valide, erreurs)
    """
    errors = []
    
    if len(password) < min_length:
        errors.append(f"Le mot de passe doit contenir au moins {min_length} caractères")
    
    if not any(char.isdigit() for char in password):
        errors.append("Le mot de passe doit contenir au moins un chiffre")
    
    if not any(char.isupper() for char in password):
        errors.append("Le mot de passe doit contenir au moins une majuscule")
    
    if not any(char.islower() for char in password):
        errors.append("Le mot de passe doit contenir au moins une minuscule")
    
    special_chars = set("!@#$%^&*(),.?\":{}|<>")
    if not any(char in special_chars for char in password):
        errors.append("Le mot de passe doit contenir au moins un caractère spécial")
    
    return len(errors) == 0, errors


def validate_phone(phone: str) -> bool:
    """
    Valide un numéro de téléphone.
    
    Args:
        phone: Numéro de téléphone à valider
        
    Returns:
        bool: True si le numéro est valide, False sinon
    """
    import re
    # Format international: +33612345678 ou 0612345678
    phone_regex = r'^\+?[1-9]\d{1,14}$'
    return bool(re.match(phone_regex, phone))


def validate_date(date_str: str, date_format: str = '%Y-%m-%d') -> bool:
    """
    Valide une date selon un format donné.
    
    Args:
        date_str: Date sous forme de chaîne
        date_format: Format de date attendu (par défaut: YYYY-MM-DD)
        
    Returns:
        bool: True si la date est valide, False sinon
    """
    from datetime import datetime
    try:
        datetime.strptime(date_str, date_format)
        return True
    except ValueError:
        return False


def validate_file_extension(filename: str, allowed_extensions: list[str]) -> bool:
    """
    Vérifie si l'extension d'un fichier est autorisée.
    
    Args:
        filename: Nom du fichier
        allowed_extensions: Liste des extensions autorisées (ex: ['.pdf', '.jpg'])
        
    Returns:
        bool: True si l'extension est autorisée, False sinon
    """
    import os
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in [ext.lower().lstrip('.') for ext in allowed_extensions]
