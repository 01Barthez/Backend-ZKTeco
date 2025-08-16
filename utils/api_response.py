"""
Module d'exportation des fonctions de réponse API.

Ce fichier expose les fonctions de réponse API standardisées
définies dans responses.py pour une utilisation plus simple.
"""
from .responses import (
    success_response,
    error_response,
    validation_error_response,
    not_found_response,
    unauthorized_response,
    forbidden_response,
    paginated_response
)

# Alias pour la compatibilité avec le code existant
api_response = success_response

__all__ = [
    'api_response',
    'success_response',
    'error_response',
    'validation_error_response',
    'not_found_response',
    'unauthorized_response',
    'forbidden_response',
    'paginated_response'
]
