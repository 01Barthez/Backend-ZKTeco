"""
Schémas de validation pour les filtres de recherche.
"""
from marshmallow import fields, validate, ValidationError, validates
from datetime import datetime, timedelta
from .base_schema import BaseSchema


class PaginationSchema(BaseSchema):
    """
    Schéma pour la pagination des résultats.
    """
    page = fields.Int(
        load_default=1,
        validate=validate.Range(min=1, error="Le numéro de page doit être supérieur à 0"),
        description="Numéro de la page à récupérer (commence à 1)"
    )
    
    per_page = fields.Int(
        load_default=20,
        validate=validate.Range(
            min=1, 
            max=100, 
            error="Le nombre d'éléments par page doit être compris entre 1 et 100"
        ),
        description="Nombre d'éléments par page (max 100)"
    )
    
    sort_by = fields.Str(
        load_default='created_at',
        description="Champ de tri (préfixez par '-' pour un tri décroissant)"
    )


class EmployeeFilterSchema(PaginationSchema):
    """
    Schéma pour filtrer et rechercher des employés.
    """
    search = fields.Str(
        required=False,
        description="Recherche textuelle (nom, email, poste, etc.)"
    )
    
    department_id = fields.Int(
        required=False,
        description="Filtrer par ID de département"
    )
    
    is_active = fields.Bool(
        required=False,
        description="Filtrer par statut actif/inactif"
    )
    
    hire_date_from = fields.Date(
        required=False,
        description="Filtrer par date d'embauche à partir de"
    )
    
    hire_date_to = fields.Date(
        required=False,
        description="Filtrer par date d'embauche jusqu'à"
    )
    
    position = fields.Str(
        required=False,
        description="Filtrer par poste ou fonction"
    )
    
    has_biometric_id = fields.Bool(
        required=False,
        description="Filtrer les employés avec/sans ID biométrique"
    )
    
    @validates('hire_date_to')
    def validate_hire_date_range(self, value, **kwargs):
        """Valide que la plage de dates d'embauche est valide."""
        hire_date_from = self.context.get('hire_date_from')
        if hire_date_from and value and value < hire_date_from:
            raise ValidationError("La date de fin doit être postérieure à la date de début")


class LogFilterSchema(PaginationSchema):
    """
    Schéma pour filtrer et rechercher des logs de pointage.
    """
    employee_id = fields.Int(
        required=False,
        description="Filtrer par ID d'employé"
    )
    
    department_id = fields.Int(
        required=False,
        description="Filtrer par ID de département"
    )
    
    action = fields.Str(
        required=False,
        validate=validate.OneOf(
            ['check_in', 'check_out', 'break_start', 'break_end', 'overtime_start', 'overtime_end', 'other']
        ),
        description="Filtrer par type d'action"
    )
    
    status = fields.Str(
        required=False,
        validate=validate.OneOf(['pending', 'approved', 'rejected', 'corrected']),
        description="Filtrer par statut de validation"
    )
    
    date_from = fields.Date(
        required=False,
        description="Filtrer à partir de cette date (inclusive)"
    )
    
    date_to = fields.Date(
        required=False,
        description="Filtrer jusqu'à cette date (inclusive)"
    )
    
    time_from = fields.Time(
        required=False,
        description="Filtrer à partir de cette heure (inclusif)"
    )
    
    time_to = fields.Time(
        required=False,
        description="Filtrer jusqu'à cette heure (inclusif)"
    )
    
    device_id = fields.Str(
        required=False,
        description="Filtrer par ID de dispositif"
    )
    
    @validates('date_to')
    def validate_date_range(self, value, **kwargs):
        """Valide que la plage de dates est valide."""
        date_from = self.context.get('date_from')
        if date_from and value and value < date_from:
            raise ValidationError("La date de fin doit être postérieure à la date de début")


class DepartmentFilterSchema(PaginationSchema):
    """
    Schéma pour filtrer et rechercher des départements.
    """
    search = fields.Str(
        required=False,
        description="Recherche textuelle (nom, code, description)"
    )
    
    parent_id = fields.Int(
        required=False,
        allow_none=True,
        description="Filtrer par ID du département parent (null pour les départements racine)"
    )
    
    is_active = fields.Bool(
        required=False,
        description="Filtrer par statut actif/inactif"
    )
    
    has_employees = fields.Bool(
        required=False,
        description="Filtrer les départements avec/sans employés"
    )


# Instances des schémas pour une utilisation facile
pagination_schema = PaginationSchema()
employee_filter_schema = EmployeeFilterSchema()
log_filter_schema = LogFilterSchema()
department_filter_schema = DepartmentFilterSchema()
