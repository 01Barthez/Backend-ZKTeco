"""
Schémas de validation pour les départements.
"""
from marshmallow import fields, validate, validates, ValidationError, post_load
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema

from models.department import Department
from .base_schema import BaseSchema


class DepartmentSchema(BaseSchema, SQLAlchemyAutoSchema):
    """
    Schéma pour la sérialisation/désérialisation des départements.
    """
    
    class Meta:
        model = Department
        load_instance = True
        include_fk = True
        include_relationships = True
    
    # Champs en lecture seule (retournés dans les réponses API)
    id = fields.Int(dump_only=True, description="ID unique du département")
    created_at = fields.DateTime(dump_only=True, format='iso', 
                               description="Date de création")
    updated_at = fields.DateTime(dump_only=True, format='iso',
                               description="Date de dernière mise à jour")
    
    # Champs modifiables
    name = fields.Str(
        required=True,
        validate=validate.Length(
            min=2, 
            max=100,
            error="Le nom du département doit contenir entre {min} et {max} caractères"
        ),
        description="Nom du département"
    )
    
    code = fields.Str(
        required=False,
        validate=validate.Length(max=10),
        description="Code court du département (optionnel)"
    )
    
    description = fields.Str(
        required=False,
        allow_none=True,
        description="Description du département"
    )
    
    is_active = fields.Bool(
        load_default=True,
        description="Indique si le département est actif"
    )
    
    # Relations
    parent_id = fields.Int(
        required=False,
        allow_none=True,
        description="ID du département parent (pour les hiérarchies)"
    )
    
    parent = fields.Nested(
        'DepartmentSchema', 
        exclude=('parent', 'children', 'employees'),
        dump_only=True,
        description="Département parent"
    )
    
    children = fields.Nested(
        'DepartmentSchema', 
        many=True, 
        exclude=('parent', 'children', 'employees'),
        dump_only=True,
        description="Sous-départements"
    )
    
    employees = fields.Nested(
        'EmployeeSchema', 
        many=True, 
        exclude=('department', 'logs'),
        dump_only=True,
        description="Employés du département"
    )
    
    # Validations personnalisées
    @validates('name')
    def validate_name(self, value):
        """Valide l'unicité du nom du département."""
        from models import db
        
        # Vérifie si un département avec le même nom existe déjà
        query = Department.query.filter(Department.name.ilike(value))
        
        # Si c'est une mise à jour, on exclut l'instance actuelle
        if 'instance' in self.context:
            query = query.filter(Department.id != self.context['instance'].id)
        
        if query.first() is not None:
            raise ValidationError("Un département avec ce nom existe déjà")
    
    @validates('code')
    def validate_code(self, value):
        """Valide l'unicité du code du département si fourni."""
        if not value:
            return
            
        from models import db
        
        # Vérifie si un département avec le même code existe déjà
        query = Department.query.filter(Department.code.ilike(value))
        
        # Si c'est une mise à jour, on exclut l'instance actuelle
        if 'instance' in self.context:
            query = query.filter(Department.id != self.context['instance'].id)
        
        if query.first() is not None:
            raise ValidationError("Ce code de département est déjà utilisé")
    
    @validates('parent_id')
    def validate_parent_id(self, value):
        """Vérifie que le département parent existe si spécifié."""
        if value is not None:
            from models import db
            if not db.session.get(Department, value):
                raise ValidationError("Le département parent spécifié n'existe pas")
    
    @post_load
    def process_department_data(self, data, **kwargs):
        """Traitement après chargement des données."""
        # Nettoyage des chaînes de caractères
        if 'name' in data and data['name']:
            data['name'] = ' '.join(data['name'].strip().split())  # Supprime les espaces multiples
        
        if 'code' in data and data['code']:
            data['code'] = data['code'].strip().upper()  # Met en majuscules
            
        if 'description' in data and data['description']:
            data['description'] = data['description'].strip()
            
        return data


# Instances des schémas pour une utilisation facile
department_schema = DepartmentSchema()
department_list_schema = DepartmentSchema(many=True, exclude=('employees', 'children'))
department_tree_schema = DepartmentSchema(many=True, exclude=('parent', 'employees'))

# Schéma pour la création (exclut les champs en lecture seule)
department_create_schema = DepartmentSchema(
    exclude=('id', 'created_at', 'updated_at', 'parent', 'children', 'employees')
)

# Schéma pour la mise à jour (exclut les champs en lecture seule et rend les champs optionnels)
department_update_schema = DepartmentSchema(
    exclude=('id', 'created_at', 'updated_at', 'parent', 'children', 'employees'),
    partial=True
)
