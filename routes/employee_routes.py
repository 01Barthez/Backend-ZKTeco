from flask import Blueprint, request, jsonify
from models.employee import Employee
from models.department import Department
from models import db
from schemas.employee_schema import EmployeeSchema
from flask_jwt_extended import jwt_required, get_jwt_identity
from models.user import User
from zk import ZK

employee_bp = Blueprint('employees', __name__, url_prefix='/api/employees')

employee_schema = EmployeeSchema()
employees_schema = EmployeeSchema(many=True)

def is_admin():
    identity = get_jwt_identity()
    user = User.query.filter_by(id=identity).first()
    return user and user.is_admin

# --- POST create employee ---
@employee_bp.route('', methods=['POST'])
@jwt_required()
def add_employee():
    if not is_admin():
        return jsonify({"msg": "Accès refusé, administrateur uniquement"}), 403
    data = request.get_json()
    errors = employee_schema.validate(data)
    if errors:
        return jsonify(errors), 400
    
    department = None
    department_id = data.get('department_id')
    if department_id:
        department = Department.query.get(department_id)
        if not department:
            return jsonify({"msg": "Département non trouvé"}), 404

    emp = Employee(
        name=data['name'],
        biometric_id=data.get('biometric_id'),
        department=department
    )
    db.session.add(emp)
    db.session.commit()
    return jsonify(employee_schema.dump(emp)), 201

# --- GET all employees ---
@employee_bp.route('', methods=['GET'])
@jwt_required()
def get_employees():
    employees = Employee.query.all()
    return jsonify(employees_schema.dump(employees))

# --- GET one employee ---
@employee_bp.route('/<int:id>', methods=['GET'])
@jwt_required()
def get_employee(id):
    emp = Employee.query.get_or_404(id)
    return jsonify(employee_schema.dump(emp))

# --- UPDATE employee ---
@employee_bp.route('/<int:id>', methods=['PUT'])
@jwt_required()
def update_employee(id):
    if not is_admin():
        return jsonify({"msg": "Accès refusé, administrateur uniquement"}), 403
    emp = Employee.query.get_or_404(id)
    data = request.get_json()
    errors = employee_schema.validate(data, partial=True)
    if errors:
        return jsonify(errors), 400

    if 'name' in data:
        emp.name = data['name']
    if 'biometric_id' in data:
        emp.biometric_id = data['biometric_id']

    if 'department_id' in data:
        department = Department.query.get(data['department_id'])
        if not department:
            return jsonify({"msg": "Département non trouvé"}), 404
        emp.department = department

    db.session.commit()
    return jsonify(employee_schema.dump(emp))

# --- DELETE employee ---
@employee_bp.route('/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_employee(id):
    if not is_admin():
        return jsonify({"msg": "Accès refusé, administrateur uniquement"}), 403
    emp = Employee.query.get_or_404(id)
    db.session.delete(emp)
    db.session.commit()
    return '', 204

# --- NEW: Synchroniser employés depuis ZKTeco ---
@employee_bp.route('/sync', methods=['POST'])
@jwt_required()
def sync_employees():
    if not is_admin():
        return jsonify({"msg": "Accès refusé, administrateur uniquement"}), 403

    data = request.get_json() or {}
    ip = data.get("ip", "192.168.100.70")
    port = data.get("port", 4370)

    zk = ZK(ip, port=port, timeout=10)
    conn = None
    added_count = 0
    updated_count = 0

    try:
        conn = zk.connect()
        conn.disable_device()
        users = conn.get_users()

        for user in users:
            existing = Employee.query.get(user.user_id)
            if existing:
                # Mettre à jour si le nom a changé
                if existing.name != user.name:
                    existing.name = user.name
                    updated_count += 1
            else:
                # Ajouter nouvel employé
                emp = Employee(
                    id=int(user.user_id),
                    name=user.name,
                    biometric_id=str(user.user_id)
                )
                db.session.add(emp)
                added_count += 1

        db.session.commit()
        return jsonify({
            "msg": f"Synchronisation terminée",
            "new_employees": added_count,
            "updated_employees": updated_count
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": f"Erreur: {e}"}), 500
    finally:
        if conn:
            conn.enable_device()
            conn.disconnect()
#--- GET tous les employés d'un département ---
@employee_bp.route('/department/<int:department_id>', methods=['GET'])
@jwt_required()
def get_employees_by_department(department_id):
    employees = Employee.query.filter_by(department_id=department_id).all()
    return jsonify(employees_schema.dump(employees)), 200
