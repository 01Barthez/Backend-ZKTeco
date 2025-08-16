"""
Documentation Swagger pour l'API RH/Pointage.
Cette documentation est générée automatiquement à partir des routes existantes.
"""
from flask_restx import Api, fields
from flask import Blueprint

# Création du blueprint pour la documentation
swagger_bp = Blueprint('swagger', __name__)

# Configuration de l'API
api = Api(
    swagger_bp,
    version='1.0',
    title='API RH/Pointage',
    description='Documentation complète de l\'API RH/Pointage',
    doc='/docs',
    default='Authentification',
    default_label='Opérations d\'authentification',
    security='Bearer Auth',
    authorizations={
        'Bearer Auth': {
            'type': 'apiKey',
            'in': 'header',
            'name': 'Authorization',
            'description': 'Utiliser le format: Bearer {token}'
        }
    },
    contact='support@votresociete.com',
    license='Propriétaire',
    license_url='https://votresociete.com/terms',
    ordered=True
)

# Modèles de données communs
error_model = api.model('Error', {
    'status': fields.String(description='Statut de la requête', example='error'),
    'message': fields.String(description='Message d\'erreur', example='Une erreur est survenue'),
    'errors': fields.Raw(description='Détails des erreurs de validation')
})

success_model = api.model('Success', {
    'status': fields.String(description='Statut de la requête', example='success'),
    'message': fields.String(description='Message de succès'),
    'data': fields.Raw(description='Données de la réponse')
})

# Modèles d'authentification
user_model = api.model('User', {
    'id': fields.Integer(readOnly=True, description='ID unique de l\'utilisateur'),
    'username': fields.String(required=True, description='Nom d\'utilisateur unique'),
    'email': fields.String(required=True, description='Adresse email valide'),
    'is_active': fields.Boolean(description='Indique si le compte est actif'),
    'is_admin': fields.Boolean(description='Indique si l\'utilisateur est administrateur'),
    'created_at': fields.DateTime(description='Date de création du compte'),
    'updated_at': fields.DateTime(description='Date de dernière mise à jour')
})

token_model = api.model('Token', {
    'access_token': fields.String(required=True, description='Jeton d\'accès JWT'),
    'refresh_token': fields.String(required=True, description='Jeton de rafraîchissement'),
    'token_type': fields.String(description='Type de jeton', default='bearer'),
    'expires_in': fields.Integer(description='Durée de validité en secondes')
})

login_model = api.model('LoginCredentials', {
    'username': fields.String(required=True, description='Nom d\'utilisateur ou email'),
    'password': fields.String(required=True, description='Mot de passe')
})

refresh_token_model = api.model('RefreshToken', {
    'refresh_token': fields.String(required=True, description='Jeton de rafraîchissement')
})

# Modèle pour les employés
employee_model = api.model('Employee', {
    'id': fields.Integer(readOnly=True, description='ID unique de l\'employé'),
    'name': fields.String(required=True, description='Nom complet de l\'employé'),
    'biometric_id': fields.String(description='ID biométrique de l\'employé'),
    'department_id': fields.Integer(description='ID du département de l\'employé'),
    'created_at': fields.DateTime(description='Date de création'),
    'updated_at': fields.DateTime(description='Date de dernière mise à jour')
})

# Modèle pour la synchronisation des employés
sync_employee_model = api.model('SyncEmployeeRequest', {
    'device_ip': fields.String(required=True, description='Adresse IP du dispositif ZKTeco'),
    'port': fields.Integer(default=4370, description='Port du dispositif ZKTeco'),
    'timeout': fields.Integer(default=5, description='Délai d\'attente en secondes')
})

# Création du namespace pour les employés
employee_ns = api.namespace('employees', description='Opérations liées aux employés')

# Définition des routes pour les employés
@employee_ns.route('')
class EmployeeList(Resource):
    @employee_ns.doc('list_employees')
    @employee_ns.marshal_list_with(employee_model, code=200, description='Liste des employés')
    @employee_ns.response(401, 'Non authentifié', error_model)
    @employee_ns.response(403, 'Accès refusé', error_model)
    @employee_ns.doc(security='Bearer Auth')
    def get(self):
        """Récupère la liste de tous les employés"""
        pass
    
    @employee_ns.doc('create_employee')
    @employee_ns.expect(employee_model)
    @employee_ns.marshal_with(employee_model, code=201, description='Employé créé avec succès')
    @employee_ns.response(400, 'Données invalides', error_model)
    @employee_ns.response(401, 'Non authentifié', error_model)
    @employee_ns.response(403, 'Accès refusé - Admin uniquement', error_model)
    @employee_ns.doc(security='Bearer Auth')
    def post(self):
        """Crée un nouvel employé (Admin uniquement)"""
        pass

@employee_ns.route('/<int:employee_id>')
@employee_ns.param('employee_id', 'ID de l\'employé')
@employee_ns.response(404, 'Employé non trouvé', error_model)
class EmployeeResource(Resource):
    @employee_ns.doc('get_employee')
    @employee_ns.marshal_with(employee_model, code=200, description='Détails de l\'employé')
    @employee_ns.response(401, 'Non authentifié', error_model)
    @employee_ns.doc(security='Bearer Auth')
    def get(self, employee_id):
        """Récupère les détails d'un employé spécifique"""
        pass
    
    @employee_ns.doc('update_employee')
    @employee_ns.expect(employee_model)
    @employee_ns.marshal_with(employee_model, code=200, description='Employé mis à jour avec succès')
    @employee_ns.response(400, 'Données invalides', error_model)
    @employee_ns.response(401, 'Non authentifié', error_model)
    @employee_ns.response(403, 'Accès refusé - Admin uniquement', error_model)
    @employee_ns.doc(security='Bearer Auth')
    def put(self, employee_id):
        """Met à jour un employé existant (Admin uniquement)"""
        pass
    
    @employee_ns.doc('delete_employee')
    @employee_ns.response(204, 'Employé supprimé avec succès')
    @employee_ns.response(401, 'Non authentifié', error_model)
    @employee_ns.response(403, 'Accès refusé - Admin uniquement', error_model)
    @employee_ns.doc(security='Bearer Auth')
    def delete(self, employee_id):
        """Supprime un employé (Admin uniquement)"""
        pass

@employee_ns.route('/sync')
class EmployeeSync(Resource):
    @employee_ns.doc('sync_employees')
    @employee_ns.expect(sync_employee_model)
    @employee_ns.marshal_list_with(employee_model, code=200, description='Liste des employés synchronisés')
    @employee_ns.response(400, 'Données invalides', error_model)
    @employee_ns.response(401, 'Non authentifié', error_model)
    @employee_ns.response(403, 'Accès refusé - Admin uniquement', error_model)
    @employee_ns.doc(security='Bearer Auth')
    def post(self):
        """Synchronise les employés avec un dispositif ZKTeco (Admin uniquement)"""
        pass

@employee_ns.route('/department/<int:department_id>')
@employee_ns.param('department_id', 'ID du département')
class DepartmentEmployees(Resource):
    @employee_ns.doc('get_employees_by_department')
    @employee_ns.marshal_list_with(employee_model, code=200, description='Liste des employés du département')
    @employee_ns.response(401, 'Non authentifié', error_model)
    @employee_ns.doc(security='Bearer Auth')
    def get(self, department_id):
        """Récupère la liste des employés d'un département spécifique"""
        pass

# Modèle pour les départments
department_model = api.model('Department', {
    'id': fields.Integer(readOnly=True, description='ID unique du département'),
    'name': fields.String(required=True, description='Nom du département', example='Ressources Humaines'),
    'created_at': fields.DateTime(description='Date de création', readonly=True),
    'updated_at': fields.DateTime(description='Date de dernière mise à jour', readonly=True)
})

# Création du namespace pour les départments
department_ns = api.namespace('departments', description='Opérations liées aux départements')

# Définition des routes pour les départments
@department_ns.route('')
class DepartmentList(Resource):
    @department_ns.doc('list_departments')
    @department_ns.marshal_list_with(department_model, code=200, description='Liste des départements')
    @department_ns.response(401, 'Non authentifié', error_model)
    @department_ns.doc(security='Bearer Auth')
    def get(self):
        """Récupère la liste de tous les départements"""
        pass
    
    @department_ns.doc('create_department')
    @department_ns.expect(department_model)
    @department_ns.marshal_with(department_model, code=201, description='Département créé avec succès')
    @department_ns.response(400, 'Données invalides', error_model)
    @department_ns.response(401, 'Non authentifié', error_model)
    @department_ns.response(403, 'Accès refusé - Admin uniquement', error_model)
    @department_ns.response(409, 'Un département avec ce nom existe déjà', error_model)
    @department_ns.doc(security='Bearer Auth')
    def post(self):
        """Crée un nouveau département (Admin uniquement)"""
        pass

@department_ns.route('/<int:department_id>')
@department_ns.param('department_id', 'ID du département')
@department_ns.response(404, 'Département non trouvé', error_model)
class DepartmentResource(Resource):
    @department_ns.doc('get_department')
    @department_ns.marshal_with(department_model, code=200, description='Détails du département')
    @department_ns.response(401, 'Non authentifié', error_model)
    @department_ns.doc(security='Bearer Auth')
    def get(self, department_id):
        """Récupère les détails d'un département spécifique"""
        pass
    
    @department_ns.doc('update_department')
    @department_ns.expect(department_model)
    @department_ns.marshal_with(department_model, code=200, description='Département mis à jour avec succès')
    @department_ns.response(400, 'Données invalides', error_model)
    @department_ns.response(401, 'Non authentifié', error_model)
    @department_ns.response(403, 'Accès refusé - Admin uniquement', error_model)
    @department_ns.response(409, 'Un département avec ce nom existe déjà', error_model)
    @department_ns.doc(security='Bearer Auth')
    def put(self, department_id):
        """Met à jour un département existant (Admin uniquement)"""
        pass
    
    @department_ns.doc('delete_department')
    @department_ns.response(204, 'Département supprimé avec succès')
    @department_ns.response(400, 'Impossible de supprimer un département contenant des employés', error_model)
    @department_ns.response(401, 'Non authentifié', error_model)
    @department_ns.response(403, 'Accès refusé - Admin uniquement', error_model)
    @department_ns.doc(security='Bearer Auth')
    def delete(self, department_id):
        """Supprime un département (Admin uniquement)"""
        pass

# Modèles pour les logs
log_model = api.model('Log', {
    'id': fields.Integer(readOnly=True, description='ID unique du log'),
    'employee_id': fields.Integer(required=True, description='ID de l\'employé concerné'),
    'timestamp': fields.DateTime(required=True, description='Date et heure du pointage', example='2025-08-15T08:30:00'),
    'biometric_id': fields.Integer(description='ID biométrique', nullable=True),
    'action': fields.String(required=True, description='Type de pointage', enum=['checkin', 'checkout'], example='checkin'),
    'created_at': fields.DateTime(description='Date de création', readonly=True),
    'updated_at': fields.DateTime(description='Date de dernière mise à jour', readonly=True)
})

sync_logs_model = api.model('SyncLogsRequest', {
    'ip': fields.String(required=True, description='Adresse IP du dispositif ZKTeco', example='192.168.1.100'),
    'port': fields.Integer(description='Port du dispositif ZKTeco', default=4370, example=4370)
})

log_query_params = api.model('LogQueryParams', {
    'employee_id': fields.Integer(description='Filtrer par ID d\'employé', example=1),
    'period': fields.String(description='Période (day/week/month)', enum=['day', 'week', 'month'], example='day'),
    'date': fields.String(description='Date de référence (format: YYYY-MM-DD)', example='2025-08-15'),
    'start_date': fields.String(description='Date de début (format: YYYY-MM-DD)', example='2025-08-01'),
    'end_date': fields.String(description='Date de fin (format: YYYY-MM-DD)', example='2025-08-15')
})

# Création du namespace pour les logs
log_ns = api.namespace('logs', description='Opérations liées aux logs de pointage')

# Définition des routes pour les logs
@log_ns.route('')
class LogList(Resource):
    @log_ns.doc('list_logs')
    @log_ns.expect(log_query_params, validate=True)
    @log_ns.marshal_list_with(log_model, code=200, description='Liste des logs')
    @log_ns.response(400, 'Paramètres de requête invalides', error_model)
    @log_ns.response(401, 'Non authentifié', error_model)
    @log_ns.doc(security='Bearer Auth')
    def get(self):
        """
        Récupère la liste des logs de pointage avec filtres.
        
        Filtres disponibles :
        - employee_id: Filtrer par ID d'employé
        - period: Période (day/week/month) - nécessite le paramètre 'date'
        - date: Date de référence (format: YYYY-MM-DD)
        - start_date/end_date: Plage de dates personnalisée
        """
        pass
    
    @log_ns.doc('create_log')
    @log_ns.expect(log_model)
    @log_ns.marshal_with(log_model, code=201, description='Log créé avec succès')
    @log_ns.response(400, 'Données invalides', error_model)
    @log_ns.response(401, 'Non authentifié', error_model)
    @log_ns.response(403, 'Accès refusé - Admin uniquement', error_model)
    @log_ns.doc(security='Bearer Auth')
    def post(self):
        """Crée un nouveau log de pointage (Admin uniquement)"""
        pass

@log_ns.route('/<int:log_id>')
@log_ns.param('log_id', 'ID du log')
@log_ns.response(404, 'Log non trouvé', error_model)
class LogResource(Resource):
    @log_ns.doc('update_log')
    @log_ns.expect(log_model)
    @log_ns.marshal_with(log_model, code=200, description='Log mis à jour avec succès')
    @log_ns.response(400, 'Données invalides', error_model)
    @log_ns.response(401, 'Non authentifié', error_model)
    @log_ns.response(403, 'Accès refusé - Admin uniquement', error_model)
    @log_ns.doc(security='Bearer Auth')
    def put(self, log_id):
        """Met à jour un log existant (Admin uniquement)"""
        pass
    
    @log_ns.doc('delete_log')
    @log_ns.response(204, 'Log supprimé avec succès')
    @log_ns.response(401, 'Non authentifié', error_model)
    @log_ns.response(403, 'Accès refusé - Admin uniquement', error_model)
    @log_ns.doc(security='Bearer Auth')
    def delete(self, log_id):
        """Supprime un log (Admin uniquement)"""
        pass

@log_ns.route('/sync')
class LogSync(Resource):
    @log_ns.doc('sync_logs')
    @log_ns.expect(sync_logs_model)
    @log_ns.marshal_with(api.model('SyncLogsResponse', {
        'msg': fields.String(description='Message de statut'),
        'new_logs': fields.Integer(description='Nombre de nouveaux logs importés'),
        'new_employees': fields.Integer(description='Nombre de nouveaux employés détectés')
    }), code=200, description='Logs synchronisés avec succès')
    @log_ns.response(400, 'Données invalides', error_model)
    @log_ns.response(401, 'Non authentifié', error_model)
    @log_ns.response(403, 'Accès refusé - Admin uniquement', error_model)
    @log_ns.doc(security='Bearer Auth')
    def post(self):
        """
        Synchronise les logs depuis un dispositif ZKTeco (Admin uniquement)
        
        Cette opération peut prendre du temps en fonction du nombre de logs à importer.
        """
        pass

# Création du namespace pour les rapports
report_ns = api.namespace('reports', description='Opérations liées aux rapports')

# Modèles pour les réponses de rapports
report_employee_model = api.model('EmployeeReport', {
    'id': fields.Integer(description='ID de l\'employé'),
    'name': fields.String(description='Nom de l\'employé'),
    'department': fields.String(description='Département'),
    'checkin_count': fields.Integer(description='Nombre de pointages d\'entrée'),
    'checkout_count': fields.Integer(description='Nombre de pointages de sortie'),
    'last_checkin': fields.DateTime(description='Dernière entrée enregistrée'),
    'last_checkout': fields.DateTime(description='Dernière sortie enregistrée')
})

# Définition des routes pour les rapports
@report_ns.route('/employees/pdf')
class EmployeePDFReport(Resource):
    @report_ns.doc('export_employees_pdf')
    @report_ns.produces(['application/pdf'])
    @report_ns.response(200, 'Rapport PDF généré avec succès', {
        'type': 'file',
        'format': 'binary'
    })
    @report_ns.response(401, 'Non authentifié', error_model)
    @report_ns.doc(security='Bearer Auth')
    def get(self):
        """
        Exporte un rapport des employés au format PDF.
        
        Retourne un fichier PDF téléchargeable contenant la liste des employés avec leurs statistiques.
        """
        pass

@report_ns.route('/employees/xlsx')
class EmployeeXLSXReport(Resource):
    @report_ns.doc('export_employees_xlsx')
    @report_ns.produces(['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'])
    @report_ns.response(200, 'Rapport Excel généré avec succès', {
        'type': 'file',
        'format': 'binary'
    })
    @report_ns.response(401, 'Non authentifié', error_model)
    @report_ns.doc(security='Bearer Auth')
    def get(self):
        """
        Exporte un rapport des employés au format Excel (XLSX).
        
        Retourne un fichier Excel téléchargeable contenant la liste des employés avec leurs statistiques.
        """
        pass

# Import et enregistrement des namespaces
from routes.auth_routes import auth_ns

# Enregistrement des namespaces
api.add_namespace(auth_ns, path='/auth')
api.add_namespace(employee_ns, path='/employees')
api.add_namespace(department_ns, path='/departments')
api.add_namespace(log_ns, path='/logs')
api.add_namespace(report_ns, path='/reports')

# Configuration de la documentation
api.doc(security='Bearer Auth')

# Fonction pour ajouter la documentation Swagger à l'application
def init_swagger(app):
    """Initialise la documentation Swagger pour l'application"""
    app.register_blueprint(swagger_bp, url_prefix='/api')
    return api
