from io import BytesIO
import pandas as pd

# Vérifier si reportlab est disponible
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

def generate_pdf_report(employees):
    """
    Génère un rapport PDF des employés.
    
    Args:
        employees: Liste des employés à inclure dans le rapport
        
    Returns:
        BytesIO: Flux binaire contenant le PDF généré
        
    Raises:
        ImportError: Si reportlab n'est pas installé
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError(
            "La génération de PDF nécessite le module 'reportlab'. "
            "Veuillez l'installer avec: pip install reportlab"
        )
        
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
