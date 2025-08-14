from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import pandas as pd

def generate_pdf_report(employees):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.setFont("Helvetica", 14)
    p.drawString(50, 750, "Rapport de Présence des Employés")
    y = 720
    for emp in employees:
        p.drawString(50, y, f"ID: {emp.id} - Nom: {emp.name}")
        y -= 20
        if y < 50:
            p.showPage()
            y = 750
    p.save()
    buffer.seek(0)
    return buffer

def generate_xlsx_report(employees):
    df = pd.DataFrame([{'ID': e.id, 'Nom': e.name} for e in employees])
    buffer = BytesIO()
    with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Employés')
    buffer.seek(0)
    return buffer
