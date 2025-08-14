from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

def create_pdf(employees):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, height - 50, "Rapport des employés")

    p.setFont("Helvetica", 12)
    y = height - 80

    for emp in employees:
        line = f"ID: {emp.id}, Nom: {emp.name}, Email: {emp.email}, Poste: {emp.position}"
        p.drawString(50, y, line)
        y -= 20
        if y < 50:
            p.showPage()
            y = height - 50

    p.save()
    buffer.seek(0)
    return buffer
