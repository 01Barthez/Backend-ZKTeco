# 📄 Spécifications Fonctionnelles & Techniques – Backend ZKTeco

## 1. 🎯 Objectif du projet

Le backend permet de gérer les **employés**, **départements** et **logs biométriques** issus d’un dispositif **ZKTeco**.  
Il fournit une **API RESTful sécurisée** permettant à un frontend ou à d’autres services d’exploiter ces données.

---

## 2. 📌 Spécifications Fonctionnelles

### 2.1 Gestion des utilisateurs & authentification

- **Connexion** via nom/mot de passe avec génération d’un **token JWT**
- **Gestion des rôles** :
  - **Admin** : accès complet à toutes les ressources
  - **User** : accès en lecture seule aux employés, départements et logs
- **Création, modification et suppression** d’utilisateurs (réservé aux admins)

---

### 2.2 Gestion des employés

- Ajouter un employé avec :
  - `id` (identifiant unique du ZKTeco)
  - `name` (nom complet)
  - `privilege` (niveau d’accès ZKTeco)
  - `password` (optionnel, s’il existe dans le terminal)
- Modifier et supprimer un employé
- Lister tous les employés ou un employé spécifique
- Association possible à un **département**

---

### 2.3 Gestion des départements

- Ajouter un département avec :
  - `id`
  - `name`
- Modifier et supprimer un département
- Lister tous les départements

---

### 2.4 Gestion des logs biométriques

- Récupération automatique depuis un terminal ZKTeco :
  - **`biometric_id`** : identifiant de l’utilisateur dans le terminal
  - **`timestamp`** : date et heure de l’événement
  - **`status`** : type de pointage (`0 = checkin`, `1 = checkout`)
  - **`action`** : libellé interprété (`checkin` ou `checkout`)
- Stockage uniquement des nouveaux logs
- Consultation des logs filtrés par :
  - Employé
  - Plage de dates
  - Type d’action

---

### 2.5 Synchronisation avec le terminal ZKTeco

- Connexion TCP/IP au terminal via l’IP et le port (`4370` par défaut)
- Désactivation temporaire du terminal pendant la récupération des données
- Lecture des utilisateurs et des pointages
- Réactivation du terminal après la lecture

---

## 3. 🛠️ Spécifications Techniques

### 3.1 Environnement

- **Langage** : Python 3.10+
- **Framework** : Flask
- **ORM** : SQLAlchemy
- **Base de données** : PostgreSQL
- **Authentification** : JWT (via Flask-JWT-Extended)
- **Gestion des migrations** : Alembic / Flask-Migrate
- **Interopérabilité ZKTeco** : bibliothèque `zk`

---

### 3.2 Modèles de données

#### **Employee**

| Champ        | Type     | Obligatoire | Description |
|--------------|----------|-------------|-------------|
| id           | int      | ✅ | Identifiant unique (correspond à celui du ZKTeco) |
| name         | string   | ✅ | Nom complet |
| privilege    | int      | ✅ | Niveau d’accès |
| password     | string   | ❌ | Mot de passe si défini |
| department_id| int (FK) | ❌ | Lien vers le département |

#### **Department**

| Champ | Type | Obligatoire | Description |
|-------|------|-------------|-------------|
| id    | int  | ✅          | Identifiant |
| name  | str  | ✅          | Nom du département |

#### **Log**

| Champ        | Type     | Obligatoire | Description |
|--------------|----------|-------------|-------------|
| id           | int      | ✅          | Identifiant |
| employee_id  | int (FK) | ✅          | Employé concerné |
| biometric_id | int      | ✅          | ID biométrique du ZKTeco |
| timestamp    | datetime | ✅          | Date/heure du pointage |
| action       | string   | ✅          | checkin / checkout |

---

## 📦 Installation

### 1️⃣ Cloner le projet

```bash
git clone <URL_DU_REPO>
cd backend

python3 -m venv envzk311
source env/bin/activate   # Linux / Mac
env\Scripts\activate      # Windows

FLASK_APP=manage.py
FLASK_ENV=development
SECRET_KEY=une_chaine_secrete
DATABASE_URL=postgresql://postgres:12032004@localhost/zkteco_db
JWT_SECRET_KEY=une_autre_chaine_secrete


psql -U postgres -h localhost
CREATE DATABASE zkteco_db;

pip install -r requirements.txt                   #pour installer les dependances

pas necessaire mais utile pour les migration :

flask db init        # seulement la 1ère fois
flask db migrate -m "Initial migration"
flask db upgrade

les end points principaux :
Méthode Endpoint                 Description             Authentification
POST /api/auth/login          Connexion utilisateur                  ❌
POST /api/employees            Ajouter un employé              ✅ Admin
GET /api/employees            Liste des employés              ✅
GET /api/employees/<id>   Détails d’un employé              ✅
PUT /api/employees/<id>   Modifier un employé              ✅ Admin
DELETE /api/employees/<id>   Supprimer un employé              ✅ Admin
GET /api/departments  Liste des départements              ✅
POST /api/logs/fetch         Récupérer les logs du ZKTeco      ✅ Admin



