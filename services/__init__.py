from .auth import (
    generate_tokens,
    check_password_strength,
    log_security_event,
    AuthenticationError,
    UserNotFoundError,
    InvalidCredentialsError,
    AccountInactiveError,
    RevokedTokenError,
    RateLimitExceededError
)
from .attendance import calculate_lateness, calculate_early_leave

# Importer les fonctions d'export de manière conditionnelle
try:
    from .export import generate_pdf_report, generate_xlsx_report
    EXPORT_AVAILABLE = True
except ImportError as e:
    # Si les dépendances d'export ne sont pas disponibles, définir des fonctions factices
    EXPORT_AVAILABLE = False
    
    def generate_pdf_report(*args, **kwargs):
        raise ImportError(
            "La génération de PDF nécessite des dépendances supplémentaires. "
            "Veuillez installer les dépendances avec: pip install reportlab"
        )
    
    def generate_xlsx_report(*args, **kwargs):
        raise ImportError(
            "La génération de fichiers Excel nécessite des dépendances supplémentaires. "
            "Veuillez installer les dépendances avec: pip install openpyxl"
        )

from .zkteco_service import store_logs_from_device

__all__ = [
    'generate_tokens',
    'check_password_strength',
    'log_security_event',
    'calculate_lateness',
    'calculate_early_leave',
    'generate_pdf_report',
    'generate_xlsx_report',
    'store_logs_from_device',
    'EXPORT_AVAILABLE',
    'AuthenticationError',
    'UserNotFoundError',
    'InvalidCredentialsError',
    'AccountInactiveError',
    'RevokedTokenError',
    'RateLimitExceededError'
]
