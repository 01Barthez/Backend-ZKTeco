"""
Schémas de validation pour les employés.
"""
from marshmallow import fields, validate, validates, ValidationError, post_load
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema, auto_field
from datetime import datetime
import re

from models.employee import Employee
from models.department import Department
from .base_schema import BaseSchema
from .log_schema import LogSchema


class EmployeeSchema(BaseSchema, SQLAlchemyAutoSchema):
    """
    Schéma pour la sérialisation/désérialisation des employés.
    """
    
    class Meta:
        model = Employee
        load_instance = True
        include_fk = True
        include_relationships = True
        
    # Champs en lecture seule (retournés dans les réponses API)
    id = fields.Int(dump_only=True, description="ID unique de l'employé")
    created_at = fields.DateTime(dump_only=True, format='iso', 
                               description="Date de création de l'enregistrement")
    updated_at = fields.DateTime(dump_only=True, format='iso',
                               description="Date de dernière mise à jour")
    
    # Champs modifiables
    name = fields.Str(
        required=True,
        validate=validate.Length(
            min=2, 
            max=100,
            error="Le nom doit contenir entre {min} et {max} caractères"
        ),
        description="Nom complet de l'employé"
    )
    
    email = fields.Email(
        required=False,
        allow_none=True,
        description="Adresse email professionnelle"
    )
    
    phone = fields.Str(
        required=False,
        allow_none=True,
        validate=validate.Length(max=20),
        description="Numéro de téléphone professionnel"
    )
    
    biometric_id = fields.Str(
        required=False,
        allow_none=True,
        description="Identifiant biométrique (si applicable)"
    )
    
    employee_id = fields.Str(
        required=False,
        description="Numéro d'employé ou matricule"
    )
    
    position = fields.Str(
        required=False,
        description="Poste ou fonction de l'employé"
    )
    
    hire_date = fields.Date(
        required=False,
        allow_none=True,
        description="Date d'embauche"
    )
    
    is_active = fields.Bool(
        load_default=True,
        description="Indique si l'employé est actif"
    )
    
    # Relations
    department_id = fields.Int(
        required=False,
        allow_none=True,
        description="ID du département de l'employé"
    )
    
    department = fields.Nested(
        'DepartmentSchema', 
        exclude=('employees',),
        dump_only=True,
        description="Détails du département"
    )
    
    logs = fields.Nested(
        'LogSchema', 
        many=True, 
        exclude=('employee',),
        dump_only=True,
        description="Historique des pointages"
    )
    
    # Validations personnalisées
    @validates('email')
    def validate_email(self, value):
        """Valide le format de l'email si fourni."""
        if value and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            raise ValidationError("Format d'email invalide")
    
    @validates('phone')
    def validate_phone(self, value):
        """Valide le format du numéro de téléphone si fourni."""
        if value and not re.match(r'^\+?[1-9]\d{1,14}$', value):
            raise ValidationError("Format de numéro de téléphone invalide")
    
    @validates('department_id')
    def validate_department_id(self, value):
        """Vérifie que le département existe si spécifié."""
        from models import db
        if value is not None and not db.session.get(Department, value):
            raise ValidationError(f"Le département avec l'ID {value} n'existe pas")
    
    @post_load
    def process_employee_data(self, data, **kwargs):
        """Traitement après chargement des données."""
        # Nettoyage des chaînes de caractères
        if 'name' in data and data['name']:
            data['name'] = ' '.join(data['name'].strip().split())  # Supprime les espaces multiples
        
        if 'email' in data and data['email']:
            data['email'] = data['email'].lower().strip()
            
        if 'phone' in data and data['phone']:
            # Garder uniquement les chiffres et le signe +
            data['phone'] = re.sub(r'[^0-9+]', '', data['phone'])
            
        return data


# Instances des schémas pour une utilisation facile
employee_schema = EmployeeSchema()
employee_list_schema = EmployeeSchema(many=True, exclude=('logs',))
employee_detail_schema = EmployeeSchema()

# Schéma pour la création (exclut les champs en lecture seule)
employee_create_schema = EmployeeSchema(exclude=('id', 'created_at', 'updated_at', 'logs', 'department'))

# Schéma pour la mise à jour (exclut les champs en lecture seule et rend les champs optionnels)
employee_update_schema = EmployeeSchema(
    exclude=('id', 'created_at', 'updated_at', 'logs', 'department'),
    partial=True
)
