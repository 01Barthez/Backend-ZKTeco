from . import db

class Employee(db.Model):
    __tablename__ = 'employees'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    biometric_id = db.Column(db.String(50), unique=True, nullable=True)  # Ajouté ici
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'))
    department = db.relationship('Department', back_populates='employees')
    logs = db.relationship('Log', back_populates='employee', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Employee {self.name}>'
