"""
Schémas de validation pour les logs de pointage.
"""
from marshmallow import fields, validate, validates, ValidationError, post_load
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from datetime import datetime, timezone
import re

from models.log import Log
from models.employee import Employee
from .base_schema import BaseSchema


class LogSchema(BaseSchema, SQLAlchemyAutoSchema):
    """
    Schéma pour la sérialisation/désérialisation des logs de pointage.
    """
    
    class Meta:
        model = Log
        load_instance = True
        include_fk = True
        include_relationships = True
    
    # Champs en lecture seule (retournés dans les réponses API)
    id = fields.Int(dump_only=True, description="ID unique du log")
    created_at = fields.DateTime(dump_only=True, format='iso', 
                               description="Date de création de l'enregistrement")
    
    # Champs modifiables
    timestamp = fields.DateTime(
        required=True,
        format='iso',
        description="Date et heure du pointage"
    )
    
    action = fields.Str(
        required=True,
        validate=validate.OneOf(
            ['check_in', 'check_out', 'break_start', 'break_end', 'overtime_start', 'overtime_end', 'other'],
            error="Action non valide. Doit être l'une des valeurs suivantes: 'check_in', 'check_out', 'break_start', 'break_end', 'overtime_start', 'overtime_end', 'other'"
        ),
        description="Type de pointage (check_in, check_out, break_start, break_end, etc.)"
    )
    
    device_id = fields.Str(
        required=False,
        allow_none=True,
        description="Identifiant du dispositif ayant enregistré le pointage"
    )
    
    location = fields.Str(
        required=False,
        allow_none=True,
        description="Localisation du pointage (si disponible)"
    )
    
    notes = fields.Str(
        required=False,
        allow_none=True,
        description="Notes ou commentaires supplémentaires"
    )
    
    status = fields.Str(
        required=False,
        validate=validate.OneOf(
            ['pending', 'approved', 'rejected', 'corrected'],
            error="Statut non valide. Doit être l'une des valeurs suivantes: 'pending', 'approved', 'rejected', 'corrected'"
        ),
        load_default='pending',
        description="Statut de validation du pointage"
    )
    
    # Relations
    employee_id = fields.Int(
        required=True,
        description="ID de l'employé concerné par le pointage"
    )
    
    employee = fields.Nested(
        'EmployeeSchema', 
        only=('id', 'name', 'employee_id'),
        dump_only=True,
        description="Informations de base de l'employé"
    )
    
    # Champs calculés (en lecture seule)
    date = fields.Date(
        attribute='timestamp',
        dump_only=True,
        format='%Y-%m-%d',
        description="Date du pointage (format YYYY-MM-DD)"
    )
    
    time = fields.Time(
        attribute='timestamp',
        dump_only=True,
        format='%H:%M:%S',
        description="Heure du pointage (format HH:MM:SS)"
    )
    
    # Validations personnalisées
    @validates('employee_id')
    def validate_employee_id(self, value):
        """Vérifie que l'employé existe."""
        from models import db
        if not db.session.get(Employee, value):
            raise ValidationError(f"L'employé avec l'ID {value} n'existe pas")
    
    @validates('timestamp')
    def validate_timestamp(self, value):
        """Valide que la date n'est pas dans le futur."""
        if value > datetime.now(timezone.utc):
            raise ValidationError("La date du pointage ne peut pas être dans le futur")
    
    @post_load
    def process_log_data(self, data, **kwargs):
        """Traitement après chargement des données."""
        # S'assure que le timestamp est au format timezone-aware
        if 'timestamp' in data and data['timestamp'] and data['timestamp'].tzinfo is None:
            # Si pas de timezone, on suppose que c'est en UTC
            data['timestamp'] = data['timestamp'].replace(tzinfo=timezone.utc)
            
        # Nettoyage des chaînes de caractères
        if 'device_id' in data and data['device_id']:
            data['device_id'] = data['device_id'].strip()
            
        if 'location' in data and data['location']:
            data['location'] = data['location'].strip()
            
        if 'notes' in data and data['notes']:
            data['notes'] = data['notes'].strip()
            
        return data


# Schémas spécifiques pour différentes actions
class CheckInOutSchema(LogSchema):
    """Schéma pour les pointages d'entrée/sortie."""
    
    class Meta(LogSchema.Meta):
        fields = ('id', 'timestamp', 'action', 'device_id', 'location')
    
    action = fields.Str(
        required=True,
        validate=validate.OneOf(
            ['check_in', 'check_out'],
            error="Action non valide. Doit être 'check_in' ou 'check_out'"
        )
    )


class BreakSchema(LogSchema):
    """Schéma pour les pauses."""
    
    class Meta(LogSchema.Meta):
        fields = ('id', 'timestamp', 'action', 'notes')
    
    action = fields.Str(
        required=True,
        validate=validate.OneOf(
            ['break_start', 'break_end'],
            error="Action non valide. Doit être 'break_start' ou 'break_end'"
        )
    )


# Instances des schémas pour une utilisation facile
log_schema = LogSchema()
log_list_schema = LogSchema(many=True)
check_in_out_schema = CheckInOutSchema()
break_schema = BreakSchema()

# Schéma pour la création (exclut les champs en lecture seule)
log_create_schema = LogSchema(exclude=('id', 'created_at', 'employee'))

# Schéma pour la mise à jour (exclut les champs en lecture seule et rend les champs optionnels)
log_update_schema = LogSchema(
    exclude=('id', 'created_at', 'employee', 'employee_id', 'timestamp'),
    partial=True
)
