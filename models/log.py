from . import db
from datetime import datetime

class Log(db.Model):
    __tablename__ = 'logs'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    biometric_id = db.Column(db.Integer, nullable=True) 
    action = db.Column(db.String(20), nullable=False)  # 'checkin' or 'checkout'

    employee = db.relationship('Employee', back_populates='logs', lazy='joined')

    def __repr__(self):
        return f'<Log {self.action} for emp {self.employee_id} at {self.timestamp}>'
