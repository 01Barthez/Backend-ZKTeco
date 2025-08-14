from marshmallow_sqlalchemy import SQLAlchemySchema, auto_field, fields
from models.employee import Employee
from .department_schema import DepartmentSchema
from .log_schema import LogSchema

class EmployeeSchema(SQLAlchemySchema):
    class Meta:
        model = Employee
        load_instance = True

    id = auto_field()
    name = auto_field()
    biometric_id = auto_field()  
    department = fields.Nested(DepartmentSchema)
    logs = fields.Nested(LogSchema, many=True)
