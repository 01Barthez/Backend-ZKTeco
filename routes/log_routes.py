from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from services.zkteco_service import store_logs_from_device
from models.log import Log
from models.user import User
from schemas.log_schema import LogSchema
from services.log_service import create_log, update_log, delete_log
from models import db
from datetime import datetime, timedelta

log_bp = Blueprint('logs', __name__, url_prefix='/api/logs')

log_schema = LogSchema()
logs_schema = LogSchema(many=True)

def is_admin():
    """Vérifie si l'utilisateur connecté est admin"""
    identity = get_jwt_identity()
    user = User.query.filter_by(id=identity).first()
    return user and user.is_admin

# --- Synchroniser les logs depuis le ZKTeco ---
@log_bp.route('/sync', methods=['POST'])
@jwt_required()
def sync_logs():
    if not is_admin():
        return jsonify({"msg": "Accès refusé, administrateur uniquement"}), 403

    data = request.get_json() or {}
    ip = data.get('ip', '192.168.100.70')
    port = data.get('port', 4370)

    if not ip:
        return jsonify({"msg": "IP du terminal requise"}), 400

    # Appel du service de synchronisation
    result = store_logs_from_device(ip, port=port)
    return jsonify({
        "msg": f"{result['new_logs']} nouveaux logs et {result['new_employees']} nouveaux employés insérés"
    }), 200

# --- Récupérer tous les logs avec filtres (support fin de journée) ---
@log_bp.route('', methods=['GET'])
@jwt_required()
def get_logs():
    employee_id = request.args.get('employee_id', type=int)
    period = request.args.get('period')  # day/week/month
    date_str = request.args.get('date')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    query = Log.query

    if employee_id:
        query = query.filter_by(employee_id=employee_id)

    # Priorité : start_date/end_date > period
    if start_date:
        try:
            sd = datetime.strptime(start_date, "%Y-%m-%d")
            query = query.filter(Log.timestamp >= sd)
        except ValueError:
            return jsonify({"msg": "start_date format attendu: YYYY-MM-DD"}), 400

    if end_date:
        try:
            ed = datetime.strptime(end_date, "%Y-%m-%d")
            # Fin de journée pour inclure tous les logs du jour
            ed = ed.replace(hour=23, minute=59, second=59)
            query = query.filter(Log.timestamp <= ed)
        except ValueError:
            return jsonify({"msg": "end_date format attendu: YYYY-MM-DD"}), 400

    # Si pas de start/end date, filtrer selon period
    if not (start_date or end_date) and period:
        base = datetime.strptime(date_str, "%Y-%m-%d") if date_str else datetime.now()
        if period == 'day':
            sd = base.replace(hour=0, minute=0, second=0)
            ed = base.replace(hour=23, minute=59, second=59)
        elif period == 'week':
            start_of_week = base - timedelta(days=base.weekday())
            sd = start_of_week.replace(hour=0, minute=0, second=0)
            ed = sd + timedelta(days=6, hours=23, minutes=59, seconds=59)
        elif period == 'month':
            sd = base.replace(day=1, hour=0, minute=0, second=0)
            if base.month == 12:
                next_month = base.replace(year=base.year+1, month=1, day=1)
            else:
                next_month = base.replace(month=base.month+1, day=1)
            # Fin du mois = 1er du mois suivant -1 seconde
            ed = next_month - timedelta(seconds=1)
        else:
            return jsonify({"msg": "period doit être 'day', 'week' ou 'month'"}), 400
        query = query.filter(Log.timestamp >= sd, Log.timestamp <= ed)

    logs = query.order_by(Log.timestamp.asc()).all()
    return jsonify(logs_schema.dump(logs)), 200

# --- Ajouter un log (admin seulement) ---
@log_bp.route('', methods=['POST'])
@jwt_required()
def add_log():
    if not is_admin():
        return jsonify({"msg": "Accès refusé, administrateur uniquement"}), 403

    data = request.get_json()
    errors = log_schema.validate(data)
    if errors:
        return jsonify(errors), 400

    new_log = create_log(data['employee_id'], data['timestamp'], data['action'])
    return jsonify(log_schema.dump(new_log)), 201

# --- Mettre à jour un log (admin seulement) ---
@log_bp.route('/<int:id>', methods=['PUT', 'PATCH'])
@jwt_required()
def update_log_route(id):
    if not is_admin():
        return jsonify({"msg": "Accès refusé, administrateur uniquement"}), 403

    log = Log.query.get_or_404(id)
    data = request.get_json()
    errors = log_schema.validate(data, partial=True)
    if errors:
        return jsonify(errors), 400

    updated = update_log(log, data)
    return jsonify(log_schema.dump(updated)), 200

# --- Supprimer un log (admin seulement) ---
@log_bp.route('/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_log_route(id):
    if not is_admin():
        return jsonify({"msg": "Accès refusé, administrateur uniquement"}), 403

    log = Log.query.get_or_404(id)
    delete_log(log)
    return '', 204
