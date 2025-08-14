from marshmallow_sqlalchemy import SQLAlchemySchema, auto_field
from models.department import Department

class DepartmentSchema(SQLAlchemySchema):
    class Meta:
        model = Department
        load_instance = True

    id = auto_field()
    name = auto_field()
