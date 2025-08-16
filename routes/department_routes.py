"""
Contrôleur pour la gestion des départements.
"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models.department import Department
from models import db
from models.user import User
from schemas.department_schema import DepartmentSchema

# Création du blueprint
department_bp = Blueprint('departments', __name__, url_prefix='/api/departments')

# Schémas de validation
department_schema = DepartmentSchema()
departments_schema = DepartmentSchema(many=True)

def is_admin():
    """Vérifie si l'utilisateur actuel est administrateur"""
    identity = get_jwt_identity()
    user = User.query.filter_by(id=identity).first()
    return user and user.is_admin

# --- POST create department ---
@department_bp.route('', methods=['POST'])
@jwt_required()
def add_department():
    """Crée un nouveau département (Admin uniquement)"""
    if not is_admin():
        return jsonify({"msg": "Accès refusé, administrateur uniquement"}), 403
    
    data = request.get_json()
    errors = department_schema.validate(data)
    if errors:
        return jsonify(errors), 400
    
    # Vérification de l'unicité du nom
    if Department.query.filter_by(name=data['name']).first():
        return jsonify({"msg": "Un département avec ce nom existe déjà"}), 409
    
    # Création du département
    department = Department(name=data['name'])
    db.session.add(department)
    db.session.commit()
    
    return jsonify(department_schema.dump(department)), 201

# --- GET all departments ---
@department_bp.route('', methods=['GET'])
@jwt_required()
def get_departments():
    """Récupère la liste de tous les départements"""
    departments = Department.query.all()
    return jsonify(departments_schema.dump(departments)), 200

# --- GET one department ---
@department_bp.route('/<int:department_id>', methods=['GET'])
@jwt_required()
def get_department(department_id):
    """Récupère un département par son ID"""
    department = Department.query.get_or_404(department_id)
    return jsonify(department_schema.dump(department)), 200

# --- UPDATE department ---
@department_bp.route('/<int:department_id>', methods=['PUT'])
@jwt_required()
def update_department(department_id):
    """Met à jour un département existant (Admin uniquement)"""
    if not is_admin():
        return jsonify({"msg": "Accès refusé, administrateur uniquement"}), 403
    
    department = Department.query.get_or_404(department_id)
    data = request.get_json()
    
    # Validation des données
    errors = department_schema.validate(data, partial=True)
    if errors:
        return jsonify(errors), 400
    
    # Vérification de l'unicité du nom
    if 'name' in data and data['name'] != department.name:
        if Department.query.filter_by(name=data['name']).first():
            return jsonify({"msg": "Un département avec ce nom existe déjà"}), 409
        department.name = data['name']
    
    db.session.commit()
    return jsonify(department_schema.dump(department)), 200

# --- DELETE department ---
@department_bp.route('/<int:department_id>', methods=['DELETE'])
@jwt_required()
def delete_department(department_id):
    """Supprime un département (Admin uniquement)"""
    if not is_admin():
        return jsonify({"msg": "Accès refusé, administrateur uniquement"}), 403
    
    department = Department.query.get_or_404(department_id)
    
    # Vérifier s'il y a des employés dans ce département
    if department.employees:
        return jsonify({
            "msg": "Impossible de supprimer ce département car il contient des employés"
        }), 400
    
    db.session.delete(department)
    db.session.commit()
    return '', 204
