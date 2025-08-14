from flask import Blueprint, send_file
from models.employee import Employee
from services.export import generate_pdf_report, generate_xlsx_report
from flask_jwt_extended import jwt_required

report_bp = Blueprint('reports', __name__, url_prefix='/api/reports')

@report_bp.route('/employees/pdf', methods=['GET'])
@jwt_required()
def export_pdf():
    employees = Employee.query.all()
    pdf_buffer = generate_pdf_report(employees)
    return send_file(pdf_buffer, mimetype='application/pdf', download_name='rapport_employes.pdf')

@report_bp.route('/employees/xlsx', methods=['GET'])
@jwt_required()
def export_xlsx():
    employees = Employee.query.all()
    xlsx_buffer = generate_xlsx_report(employees)
    return send_file(xlsx_buffer, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', download_name='rapport_employes.xlsx')
