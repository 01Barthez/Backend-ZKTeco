"""
Schémas de validation pour les rapports et exports.
"""
from marshmallow import fields, validate, ValidationError, validates
from datetime import datetime, timedelta
from .base_schema import BaseSchema


class DateRangeSchema(BaseSchema):
    """
    Schéma pour valider une plage de dates.
    """
    start_date = fields.Date(
        required=True,
        description="Date de début (inclusive)"
    )
    
    end_date = fields.Date(
        required=False,
        description="Date de fin (inclusive). Par défaut, aujourd'hui"
    )
    
    @validates('end_date')
    def validate_date_range(self, value, **kwargs):
        """Valide que la plage de dates est valide."""
        start_date = self.context.get('start_date')
        if start_date and value and value < start_date:
            raise ValidationError("La date de fin doit être postérieure à la date de début")
        
        # Limite la plage de dates à 1 an maximum
        if start_date and value and (value - start_date).days > 365:
            raise ValidationError("La plage de dates ne peut pas dépasser 1 an")


class AttendanceReportSchema(DateRangeSchema):
    """
    Schéma pour générer un rapport de présence.
    """
    employee_ids = fields.List(
        fields.Int(),
        required=False,
        description="Liste des ID d'employés à inclure dans le rapport. Si non spécifié, tous les employés sont inclus."
    )
    
    department_ids = fields.List(
        fields.Int(),
        required=False,
        description="Liste des ID de départements à inclure dans le rapport."
    )
    
    include_details = fields.Bool(
        load_default=False,
        description="Inclure les détails de chaque pointage dans le rapport"
    )
    
    group_by = fields.Str(
        validate=validate.OneOf(['day', 'week', 'month', 'employee', 'department', 'none']),
        load_default='day',
        description="Critère de regroupement des résultats"
    )
    
    format = fields.Str(
        validate=validate.OneOf(['json', 'csv', 'pdf', 'excel']),
        load_default='json',
        description="Format de sortie du rapport"
    )


class ExportDataSchema(DateRangeSchema):
    """
    Schéma pour exporter des données de pointage.
    """
    employee_ids = fields.List(
        fields.Int(),
        required=False,
        description="Liste des ID d'employés à exporter"
    )
    
    department_ids = fields.List(
        fields.Int(),
        required=False,
        description="Liste des ID de départements à exporter"
    )
    
    include_employee_details = fields.Bool(
        load_default=True,
        description="Inclure les détails des employés dans l'export"
    )
    
    include_department_details = fields.Bool(
        load_default=True,
        description="Inclure les détails des départements dans l'export"
    )
    
    format = fields.Str(
        validate=validate.OneOf(['json', 'csv', 'excel']),
        load_default='csv',
        description="Format d'export"
    )
    
    timezone = fields.Str(
        load_default='UTC',
        description="Fuseau horaire pour les dates d'exportation"
    )


class EmployeeAttendanceStatsSchema(BaseSchema):
    """
    Schéma pour les statistiques de présence d'un employé.
    """
    employee_id = fields.Int(required=True, description="ID de l'employé")
    
    period = fields.Str(
        validate=validate.OneOf(['day', 'week', 'month', 'year', 'custom']),
        load_default='month',
        description="Période d'analyse"
    )
    
    start_date = fields.Date(
        required=False,
        description="Date de début (requise si period='custom')"
    )
    
    end_date = fields.Date(
        required=False,
        description="Date de fin (requise si period='custom')"
    )
    
    @validates('start_date')
    def validate_start_date(self, value, **kwargs):
        """Valide que la date de début est fournie pour une période personnalisée."""
        if self.context.get('period') == 'custom' and not value:
            raise ValidationError("La date de début est requise pour une période personnalisée")
    
    @validates('end_date')
    def validate_end_date(self, value, **kwargs):
        """Valide que la date de fin est fournie pour une période personnalisée."""
        if self.context.get('period') == 'custom' and not value:
            raise ValidationError("La date de fin est requise pour une période personnalisée")


# Instances des schémas pour une utilisation facile
date_range_schema = DateRangeSchema()
attendance_report_schema = AttendanceReportSchema()
export_data_schema = ExportDataSchema()
employee_attendance_stats_schema = EmployeeAttendanceStatsSchema()
