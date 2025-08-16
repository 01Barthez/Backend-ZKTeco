"""
Module pour les réponses API standardisées.
Fournit des fonctions utilitaires pour formater les réponses API de manière cohérente.
"""
from flask import jsonify
from http import HTTPStatus
from typing import Any, Dict, Optional, Union


def success_response(
    data: Any = None,
    message: str = "Success",
    status_code: int = HTTPStatus.OK,
    **kwargs
) -> tuple:
    """
    Formatte une réponse de succès standardisée.

    Args:
        data: Les données à inclure dans la réponse.
        message: Un message décrivant le résultat de l'opération.
        status_code: Le code de statut HTTP (par défaut: 200).
        **kwargs: Champs supplémentaires à inclure dans la réponse.

    Returns:
        Un tuple (réponse JSON, code HTTP)
    """
    response = {
        "success": True,
        "message": message,
        "data": data,
        **kwargs
    }
    return jsonify(response), status_code


def error_response(
    message: str = "An error occurred",
    status_code: int = HTTPStatus.BAD_REQUEST,
    error_code: Optional[str] = None,
    errors: Optional[Dict[str, Any]] = None,
    **kwargs
) -> tuple:
    """
    Formatte une réponse d'erreur standardisée.

    Args:
        message: Un message d'erreur descriptif.
        status_code: Le code de statut HTTP (par défaut: 400).
        error_code: Un code d'erreur personnalisé pour une identification plus facile.
        errors: Un dictionnaire d'erreurs de validation détaillées.
        **kwargs: Champs supplémentaires à inclure dans la réponse.

    Returns:
        Un tuple (réponse JSON, code HTTP)
    """
    response = {
        "success": False,
        "message": message,
        "error": {
            "code": error_code or f"ERR_{status_code}",
            "message": message,
            **kwargs
        }
    }
    
    if errors:
        response["error"]["errors"] = errors
    
    return jsonify(response), status_code


def validation_error_response(
    errors: Dict[str, Any],
    message: str = "Validation failed",
    **kwargs
) -> tuple:
    """
    Formatte une réponse d'erreur de validation.

    Args:
        errors: Un dictionnaire des erreurs de validation.
        message: Un message d'erreur descriptif.
        **kwargs: Champs supplémentaires à inclure dans la réponse.

    Returns:
        Un tuple (réponse JSON, code HTTP 422)
    """
    return error_response(
        message=message,
        status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
        error_code="VALIDATION_ERROR",
        errors=errors,
        **kwargs
    )


def not_found_response(
    resource: str = "Resource",
    **kwargs
) -> tuple:
    """
    Formatte une réponse 404 Not Found standardisée.

    Args:
        resource: Le nom de la ressource introuvable.
        **kwargs: Champs supplémentaires à inclure dans la réponse.

    Returns:
        Un tuple (réponse JSON, code HTTP 404)
    """
    return error_response(
        message=f"{resource} not found",
        status_code=HTTPStatus.NOT_FOUND,
        error_code="NOT_FOUND",
        **kwargs
    )


def unauthorized_response(
    message: str = "Authentication required",
    **kwargs
) -> tuple:
    """
    Formatte une réponse 401 Unauthorized standardisée.

    Args:
        message: Un message d'erreur descriptif.
        **kwargs: Champs supplémentaires à inclure dans la réponse.

    Returns:
        Un tuple (réponse JSON, code HTTP 401)
    """
    return error_response(
        message=message,
        status_code=HTTPStatus.UNAUTHORIZED,
        error_code="UNAUTHORIZED",
        **kwargs
    )


def forbidden_response(
    message: str = "Insufficient permissions",
    **kwargs
) -> tuple:
    """
    Formatte une réponse 403 Forbidden standardisée.

    Args:
        message: Un message d'erreur descriptif.
        **kwargs: Champs supplémentaires à inclure dans la réponse.

    Returns:
        Un tuple (réponse JSON, code HTTP 403)
    """
    return error_response(
        message=message,
        status_code=HTTPStatus.FORBIDDEN,
        error_code="FORBIDDEN",
        **kwargs
    )


def paginated_response(
    items: list,
    page: int,
    per_page: int,
    total: int,
    **kwargs
) -> tuple:
    """
    Formatte une réponse paginée.

    Args:
        items: La liste des éléments pour la page actuelle.
        page: Le numéro de la page actuelle.
        per_page: Le nombre d'éléments par page.
        total: Le nombre total d'éléments.
        **kwargs: Métadonnées supplémentaires à inclure.

    Returns:
        Un tuple (réponse JSON, code HTTP 200)
    """
    from math import ceil
    
    total_pages = ceil(total / per_page) if per_page > 0 else 0
    
    response = {
        "success": True,
        "pagination": {
            "total": total,
            "count": len(items),
            "per_page": per_page,
            "current_page": page,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1
        },
        "data": items,
        **kwargs
    }
    
    return jsonify(response), HTTPStatus.OK


def too_many_requests_response(
    message: str = "Too many requests",
    retry_after: int = None,
    **kwargs
) -> tuple:
    """
    Formatte une réponse 429 Too Many Requests standardisée.

    Args:
        message: Un message d'erreur descriptif.
        retry_after: Nombre de secondes à attendre avant une nouvelle tentative.
        **kwargs: Champs supplémentaires à inclure dans la réponse.

    Returns:
        Un tuple (réponse JSON, code HTTP 429)
    """
    response = {
        "success": False,
        "message": message,
        "error": {
            "code": "TOO_MANY_REQUESTS",
            "message": message,
            **kwargs
        }
    }
    
    if retry_after is not None:
        response["retry_after"] = retry_after
    
    return jsonify(response), HTTPStatus.TOO_MANY_REQUESTS
