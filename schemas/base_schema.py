"""
Schéma de base avec des fonctionnalités communes à tous les schémas.
"""
from marshmallow import Schema, fields, post_dump, post_load
from datetime import datetime


class BaseSchema(Schema):
    """
    Classe de base pour tous les schémas de l'application.
    Fournit des fonctionnalités communes comme le formatage des dates,
    le nettoyage des données, etc.
    """
    
    class Meta:
        ordered = True  # Pour maintenir l'ordre des champs
        datetimeformat = '%Y-%m-%dT%H:%M:%S%z'
    
    # Champs communs à la plupart des modèles
    id = fields.Int(dump_only=True)
    created_at = fields.DateTime(dump_only=True, format='iso')
    updated_at = fields.DateTime(dump_only=True, format='iso')
    
    # Méthodes utilitaires communes
    @post_dump
    def remove_none_values(self, data, **kwargs):
        """
        Supprime les champs avec des valeurs None du résultat de sérialisation.
        """
        return {
            key: value for key, value in data.items() 
            if value is not None and value != [] and value != {}
        }
    
    @post_load
    def process_input_data(self, data, **kwargs):
        """
        Traitement commun des données après désérialisation.
        """
        # Supprime les champs vides ou None
        return {
            key: value for key, value in data.items() 
            if value is not None and value != ''
        }


class PaginatedSchema(Schema):
    """
    Schéma de base pour les réponses paginées.
    """
    items = fields.List(fields.Dict())
    page = fields.Int()
    per_page = fields.Int()
    total = fields.Int()
    total_pages = fields.Int()
    has_next = fields.Bool()
    has_prev = fields.Bool()
    
    @post_dump
    def add_pagination_links(self, data, **kwargs):
        """
        Ajoute des liens de pagination aux résultats.
        """
        if 'items' not in data:
            return data
            
        # Calcul des liens de pagination
        base_url = self.context.get('request_url', '').split('?')[0]
        page = data.get('page', 1)
        per_page = data.get('per_page', 10)
        total_pages = data.get('total_pages', 0)
        
        # Construction des liens
        links = {
            'self': f"{base_url}?page={page}&per_page={per_page}",
            'first': f"{base_url}?page=1&per_page={per_page}",
            'last': f"{base_url}?page={total_pages}&per_page={per_page}",
        }
        
        if page > 1:
            links['prev'] = f"{base_url}?page={page-1}&per_page={per_page}"
            
        if page < total_pages:
            links['next'] = f"{base_url}?page={page+1}&per_page={per_page}"
        
        data['_links'] = links
        return data
