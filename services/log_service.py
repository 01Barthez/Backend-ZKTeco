from models import db
from models.log import Log
from datetime import datetime

def create_log(employee_id, timestamp_str, action):
    timestamp = datetime.fromisoformat(timestamp_str)
    log = Log(employee_id=employee_id, timestamp=timestamp, action=action)
    db.session.add(log)
    db.session.commit()
    return log

def update_log(log, data):
    if 'employee_id' in data:
        log.employee_id = data['employee_id']
    if 'timestamp' in data:
        log.timestamp = datetime.fromisoformat(data['timestamp'])
    if 'action' in data:
        log.action = data['action']
    db.session.commit()
    return log

def delete_log(log):
    db.session.delete(log)
    db.session.commit()
