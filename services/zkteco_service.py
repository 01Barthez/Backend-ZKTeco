from zk import ZK
from models.log import Log
from models.employee import Employee
from models import db
from datetime import datetime

def store_logs_from_device(ip="192.168.100.70", port=4370):
    zk = ZK(ip, port=port, timeout=10)
    conn = None
    added_count = 0
    added_employees = 0
    logs_added_list = []  # Pour retourner les logs ajoutés

    try:
        conn = zk.connect()
        conn.disable_device()

        # ---- 1. Récupérer et mettre à jour les infos employés ----
        users = conn.get_users()
        existing_ids = {emp.id for emp in Employee.query.all()}
        print("IDs employés existants :", existing_ids)

        for user in users:
            if user.user_id not in existing_ids:
                new_emp = Employee(
                    id=user.user_id,
                    name=user.name,
                    privilege=getattr(user, 'privilege', None),
                    password=getattr(user, 'password', None),
                    biometric_id=getattr(user, 'finger_id', None)  # stocke l'empreinte principale
                )
                db.session.add(new_emp)
                added_employees += 1
                print(f"Nouvel employé ajouté: {user.user_id} {user.name}")

        db.session.commit()  # Commit des employés avant les logs

        # ---- 2. Récupérer les logs ----
        logs = conn.get_attendance()
        employees_db = {emp.id: emp for emp in Employee.query.all()}  # dictionnaire pour accès rapide

        for rec in logs:
            user_id = getattr(rec, 'user_id', None)
            timestamp = getattr(rec, 'timestamp', None)
            status = getattr(rec, 'status', None)
            finger_id = getattr(rec, 'finger_id', None)  # numéro de l'empreinte utilisée

            if user_id not in employees_db or timestamp is None:
                print(f"Ignoré (employé inconnu ou timestamp manquant): user_id={user_id}, timestamp={timestamp}")
                continue

            # Vérifier le statut
            if status not in (0, 1):
                print(f"Ignoré (statut inconnu): user_id={user_id}, status={status}")
                continue

            action = 'checkin' if status == 0 else 'checkout'

            # Vérifier doublon exact
            exists = Log.query.filter_by(
                employee_id=user_id,
                timestamp=timestamp,
                action=action,
                biometric_id=finger_id
            ).first()
            if exists:
                print(f"Doublon ignoré: user_id={user_id}, timestamp={timestamp}, action={action}")
                continue

            # Ajouter le log
            log = Log(
                employee_id=user_id,
                timestamp=timestamp,
                action=action,
                biometric_id=finger_id
            )
            db.session.add(log)
            added_count += 1
            logs_added_list.append({
                "employee_id": user_id,
                "timestamp": timestamp.isoformat(),
                "action": action,
                "biometric_id": finger_id
            })
            print(f"Log ajouté: {user_id} {timestamp} {action}")

        db.session.commit()

        return {
            "new_logs": added_count,
            "new_employees": added_employees,
            "logs_added": logs_added_list
        }

    except Exception as e:
        print(f"Erreur lors de la connexion ou récupération des données: {e}")
        db.session.rollback()
        return {"new_logs": 0, "new_employees": 0, "logs_added": []}

    finally:
        if conn:
            conn.enable_device()
            conn.disconnect()
