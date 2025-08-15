# Système de Gestion des Employés et Pointage

## 📋 Table des matières

- [Présentation du Projet](#-présentation-du-projet)
- [Fonctionnalités](#-fonctionnalités)
- [Stack Technique](#-stack-technique)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Utilisation](#-utilisation)
- [API Documentation](#-api-documentation)
- [Sécurité](#-sécurité)
- [Frontend Recommandé](#-frontend-recommandé)
- [Contribution](#-contribution)
- [Licence](#-licence)

## 🌟 Présentation du Projet

Ce projet est une API RESTful complète pour la gestion des employés et du système de pointage. Il permet de gérer les employés, les départements, les pointages et générer des rapports. Le système inclut une authentification sécurisée, une gestion des rôles et une intégration avec des dispositifs de pointage biométriques ZKTeco.

## 🚀 Fonctionnalités

### 🔐 Authentification et Autorisation

- Inscription et connexion des utilisateurs
- Gestion des rôles (admin, utilisateur)
- Jetons JWT pour l'authentification
- Rafraîchissement des jetons d'accès
- Réinitialisation de mot de passe sécurisée
- Protection contre les attaques par force brute

### 👥 Gestion des Employés

- Création, lecture, mise à jour et suppression des employés
- Gestion des informations personnelles et professionnelles
- Association des employés aux départements
- Historique des modifications

### 🏢 Gestion des Départements

- Création et gestion hiérarchique des départements
- Association des employés aux départements
- Visualisation de l'organigramme

### ⏱️ Gestion des Pointages

- Enregistrement des entrées/sorties
- Gestion des pauses
- Calcul automatique des heures supplémentaires
- Intégration avec les dispositifs ZKTeco
- Synchronisation des données biométriques

### 📊 Rapports et Exports

- Rapports de présence et d'absence
- Statistiques de pointage
- Export en PDF et Excel
- Filtres avancés pour l'analyse des données

### ⚙️ Administration

- Tableau de bord administratif
- Gestion des utilisateurs et des permissions
- Journalisation des activités
- Sauvegarde et restauration des données

## 🛠️ Stack Technique

### Backend

- **Framework**: Flask (Python)
- **Base de données**: PostgreSQL avec SQLAlchemy ORM
- **Authentification**: JWT (JSON Web Tokens)
- **Documentation**: Swagger/OpenAPI
- **Validation des données**: Marshmallow
- **Tâches asynchrones**: Celery (optionnel)
- **Cache**: Redis (optionnel)

### Sécurité

- Protection CSRF
- Rate Limiting
- Sécurisation des en-têtes HTTP
- Validation des entrées
- Chiffrement des mots de passe (bcrypt)

## 🚀 Installation

### Prérequis

- Python 3.8+
- PostgreSQL
- pip (gestionnaire de paquets Python)
- virtualenv (recommandé)

### Étapes d'installation

1. **Cloner le dépôt**

   ```bash
   git clone [URL_DU_REPO]
   cd backend
   ```

2. **Créer et activer un environnement virtuel**

   ```bash
   python -m venv venv
   source venv/bin/activate  # Sur Linux/Mac
   # OU
   .\venv\Scripts\activate  # Sur Windows
   ```

3. **Installer les dépendances**

   ```bash
   pip install -r requirements.txt
   ```

4. **Configurer la base de données**
   - Créer une base de données PostgreSQL
   - Mettre à jour la configuration dans `config.py`

5. **Initialiser la base de données**

   ```bash
   python manage.py db init
   python manage.py db migrate
   python manage.py db upgrade
   ```

6. **Lancer l'application**

   ```bash
   python manage.py run
   ```

## ⚙️ Configuration

Copiez le fichier `.env.example` vers `.env` et modifiez les variables selon votre environnement :

```env
FLASK_APP=main.py
FLASK_ENV=development
SECRET_KEY=votre_cle_secrete_tres_longue
DATABASE_URL=postgresql://utilisateur:motdepasse@localhost/nom_de_la_base
JWT_SECRET_KEY=votre_cle_jwt_secrete
```

## 🚀 Utilisation

### Démarrer le serveur de développement

```bash
python manage.py run
```

### Créer un utilisateur administrateur

```bash
python manage.py create_admin --username admin --password votre_mot_de_passe
```

### Exécuter les tests

```bash
pytest
```

## 📚 API Documentation

Une documentation interactive de l'API est disponible à l'adresse :

```
http://localhost:5000/api/docs
```

La documentation inclut :

- Tous les endpoints disponibles
- Les paramètres attendus
- Les réponses possibles
- La possibilité de tester les requêtes directement depuis le navigateur

## 🔒 Sécurité

### Mesures de sécurité implémentées

- Authentification par JWT avec rafraîchissement de token
- Protection contre les attaques CSRF
- Rate limiting pour prévenir les attaques par force brute
- Validation stricte des entrées utilisateur
- Mots de passe hashés avec bcrypt
- En-têtes de sécurité HTTP
- Journalisation des activités sensibles

### Bonnes pratiques recommandées

- Toujours utiliser HTTPS en production
- Mettre à jour régulièrement les dépendances
- Ne jamais exposer les clés secrètes
- Implémenter des sauvegardes régulières
- Surveiller les journaux d'activité

## 🖥️ Frontend Recommandé

### Interface Utilisateur Recommandée

L'API est conçue pour être utilisée avec une interface utilisateur moderne et réactive. Voici les attentes pour le frontend :

#### Technologies Recommandées

- **Framework**: React.js, Vue.js ou Angular
- **Gestion d'état**: Redux ou Vuex
- **UI Components**: Material-UI, Ant Design ou Vuetify
- **Gestion des formulaires**: Formik ou Vee-Validate
- **Requêtes HTTP**: Axios
- **Gestion des dates**: date-fns ou Moment.js

#### Écrans Principaux

1. **Connexion**
   - Formulaire de connexion
   - Lien de récupération de mot de passe

2. **Tableau de Bord**
   - Vue d'ensemble des présences
   - Statistiques clés
   - Alertes et notifications

3. **Gestion des Employés**
   - Liste des employés avec filtres
   - Formulaire d'ajout/édition
   - Vue détaillée d'un employé

4. **Pointage**
   - Interface de pointage
   - Historique des pointages
   - Gestion des corrections

5. **Rapports**
   - Générateur de rapports
   - Filtres avancés
   - Export PDF/Excel

#### Considérations UX/UI

- Design responsive pour mobile et desktop
- Feedback utilisateur immédiat pour les actions
- Chargement paresseux pour les grandes listes
- Validation en temps réel des formulaires
- Messages d'erreur clairs et utiles
- Thème personnalisable
- Support du mode sombre/clair

## 🤝 Contribution

Les contributions sont les bienvenues ! Voici comment contribuer :

1. Forkez le projet
2. Créez une branche pour votre fonctionnalité (`git checkout -b feature/AmazingFeature`)
3. Committez vos changements (`git commit -m 'Add some AmazingFeature'`)
4. Poussez vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrez une Pull Request

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

---

Développé avec ❤️ par [Votre Nom/Équipe] - 2025
