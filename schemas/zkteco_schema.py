"""
Schémas de validation pour l'intégration avec les appareils ZKTeco.
"""
from marshmallow import fields, validate, ValidationError, validates
from datetime import datetime, timedelta
import ipaddress
import re
from .base_schema import BaseSchema


class ZKTecoDeviceSchema(BaseSchema):
    """
    Schéma pour la configuration d'un appareil ZKTeco.
    """
    id = fields.Int(dump_only=True, description="ID unique de l'appareil")
    
    name = fields.Str(
        required=True,
        validate=validate.Length(min=2, max=100),
        description="Nom d'affichage de l'appareil"
    )
    
    ip_address = fields.Str(
        required=True,
        description="Adresse IP de l'appareil"
    )
    
    port = fields.Int(
        required=True,
        validate=validate.Range(min=1, max=65535),
        default=4370,
        description="Port de communication (défaut: 4370)"
    )
    
    timezone = fields.Str(
        required=False,
        default="UTC",
        description="Fuseau horaire de l'appareil (format: 'UTC', 'Europe/Paris', etc.)"
    )
    
    location = fields.Str(
        required=False,
        allow_none=True,
        description="Emplacement physique de l'appareil"
    )
    
    serial_number = fields.Str(
        required=False,
        allow_none=True,
        description="Numéro de série de l'appareil"
    )
    
    device_model = fields.Str(
        required=False,
        allow_none=True,
        description="Modèle de l'appareil"
    )
    
    is_active = fields.Bool(
        load_default=True,
        description="Indique si l'appareil est actif et surveillé"
    )
    
    sync_enabled = fields.Bool(
        load_default=True,
        description="Activer la synchronisation automatique avec cet appareil"
    )
    
    sync_interval = fields.Int(
        required=False,
        validate=validate.Range(min=1, max=1440),
        default=5,
        description="Intervalle de synchronisation en minutes (1-1440, défaut: 5)"
    )
    
    last_sync = fields.DateTime(
        dump_only=True,
        format='iso',
        description="Date et heure de la dernière synchronisation"
    )
    
    last_sync_status = fields.Str(
        dump_only=True,
        description="Statut de la dernière synchronisation (success, error, in_progress)"
    )
    
    last_error = fields.Str(
        dump_only=True,
        allow_none=True,
        description="Dernier message d'erreur (le cas échéant)"
    )
    
    created_at = fields.DateTime(dump_only=True, format='iso')
    updated_at = fields.DateTime(dump_only=True, format='iso')
    
    # Validations personnalisées
    @validates('ip_address')
    def validate_ip_address(self, value):
        """Valide le format de l'adresse IP."""
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise ValidationError("Adresse IP invalide")
    
    @validates('timezone')
    def validate_timezone(self, value):
        """Valide le format du fuseau horaire."""
        if value and not re.match(r'^[A-Za-z_/]+$', value):
            raise ValidationError("Format de fuseau horaire invalide")


class ZKTecoSyncSchema(BaseSchema):
    """
    Schéma pour déclencher une synchronisation manuelle avec un appareil ZKTeco.
    """
    device_id = fields.Int(
        required=False,
        description="ID de l'appareil à synchroniser. Si non spécifié, tous les appareils actifs seront synchronisés."
    )
    
    full_sync = fields.Bool(
        load_default=False,
        description="Effectuer une synchronisation complète (par défaut: uniquement les nouveaux logs)"
    )
    
    sync_users = fields.Bool(
        load_default=True,
        description="Synchroniser les utilisateurs depuis l'appareil"
    )
    
    sync_attendance = fields.Bool(
        load_default=True,
        description="Synchroniser les logs de présence depuis l'appareil"
    )
    
    start_date = fields.DateTime(
        required=False,
        format='iso',
        description="Date de début pour la synchronisation (par défaut: dernière synchronisation)"
    )
    
    end_date = fields.DateTime(
        required=False,
        format='iso',
        description="Date de fin pour la synchronisation (par défaut: maintenant)"
    )
    
    @validates('end_date')
    def validate_date_range(self, value, **kwargs):
        """Valide que la plage de dates est valide."""
        start_date = self.context.get('start_date')
        if start_date and value and value < start_date:
            raise ValidationError("La date de fin doit être postérieure à la date de début")


class ZKTecomapSchema(BaseSchema):
    """
    Schéma pour mapper les utilisateurs entre le système et un appareil ZKTeco.
    """
    employee_id = fields.Int(
        required=True,
        description="ID de l'employé dans le système"
    )
    
    device_user_id = fields.Str(
        required=True,
        description="ID de l'utilisateur sur l'appareil ZKTeco"
    )
    
    privilege = fields.Int(
        required=False,
        validate=validate.Range(min=0, max=14),
        default=0,
        description="Niveau de privilège sur l'appareil (0: utilisateur normal, 14: administrateur)"
    )
    
    password = fields.Str(
        required=False,
        allow_none=True,
        validate=validate.Length(max=8),
        description="Mot de passe pour l'appareil (max 8 chiffres)"
    )
    
    card_number = fields.Str(
        required=False,
        allow_none=True,
        description="Numéro de carte RFID (si applicable)"
    )
    
    is_active = fields.Bool(
        load_default=True,
        description="Activer/désactiver l'utilisateur sur l'appareil"
    )


# Instances des schémas pour une utilisation facile
zkteco_device_schema = ZKTecoDeviceSchema()
zkteco_device_list_schema = ZKTecoDeviceSchema(many=True)
zkteco_sync_schema = ZKTecomapSchema()
zkteco_user_map_schema = ZKTecomapSchema()
