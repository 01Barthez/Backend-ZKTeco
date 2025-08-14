import os
import sys
import random
from dotenv import load_dotenv
from flask import Flask

# Ajouter backend/ au PYTHONPATH pour que les imports fonctionnent
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend"))

from models import db, Employee, Department

# Charger les variables d'environnement depuis .env
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL n'est pas défini dans le fichier .env")

# Créer une app Flask temporaire
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Attribution aléatoire des départements
with app.app_context():
    employees = Employee.query.all()
    departments = Department.query.all()

    if not departments:
        print("❌ Aucun département trouvé dans la base !")
    else:
        for emp in employees:
            dept = random.choice(departments)
            emp.department = dept
            print(f"✅ {emp.name} -> {dept.name}")

        db.session.commit()
        print("🎉 Tous les employés ont reçu un département aléatoire !")
