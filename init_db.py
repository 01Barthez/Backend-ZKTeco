import os
import sys
from dotenv import load_dotenv
from flask import Flask

# 🔹 Ajouter backend/ au PYTHONPATH pour que les imports fonctionnent
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from models import db, User, Employee, Department, Log

# Charger les variables d'environnement depuis .env
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL n'est pas défini dans le fichier .env")

# Créer une application Flask temporaire pour initialiser la DB
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Créer toutes les tables
with app.app_context():
    print("📦 Création des tables dans la base de données...")
    db.create_all()
    print("✅ Base de données initialisée avec succès.")
