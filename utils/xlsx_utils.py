from io import BytesIO
from openpyxl import Workbook

def create_xlsx(employees):
    output = BytesIO()
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Employés"

    headers = ["ID", "Nom", "Email", "Poste"]
    sheet.append(headers)

    for emp in employees:
        sheet.append([emp.id, emp.name, emp.email, emp.position])

    workbook.save(output)
    output.seek(0)
    return output
