from marshmallow import Schema, fields

class LogSchema(Schema):
    id = fields.Int(dump_only=True)
    employee_id = fields.Int(required=True)
    timestamp = fields.DateTime(required=True)
    action = fields.Str(required=True)
