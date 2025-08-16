"""
Module d'exportation des schémas de validation de l'application.

Ce module expose tous les schémas de validation utilisés dans l'API,
organisés par domaine fonctionnel.
"""

# Schémas de base
from .base_schema import BaseSchema, PaginatedSchema

# Schémas d'authentification et utilisateurs
from .user_schema import (
    UserSchema, user_schema, user_list_schema, user_create_schema,
    UserCreateSchema, LoginSchema, login_schema,
    RefreshTokenSchema, refresh_token_schema,
    ChangePasswordSchema, change_password_schema,
    PasswordResetRequestSchema, password_reset_request_schema,
    PasswordResetSchema, password_reset_schema
)

# Schémas des employés
from .employee_schema import (
    EmployeeSchema, employee_schema, employee_list_schema,
    employee_detail_schema, employee_create_schema, employee_update_schema
)

# Schémas des départements
from .department_schema import (
    DepartmentSchema, department_schema, department_list_schema,
    department_tree_schema, department_create_schema, department_update_schema
)

# Schémas des logs de pointage
from .log_schema import (
    LogSchema, log_schema, log_list_schema, log_create_schema, log_update_schema,
    CheckInOutSchema, check_in_out_schema,
    BreakSchema, break_schema
)

# Schémas pour les rapports et exports
from .report_schema import (
    DateRangeSchema, date_range_schema,
    AttendanceReportSchema, attendance_report_schema,
    ExportDataSchema, export_data_schema,
    EmployeeAttendanceStatsSchema, employee_attendance_stats_schema
)

# Schémas pour le filtrage et la recherche
from .filter_schema import (
    PaginationSchema, pagination_schema,
    EmployeeFilterSchema, employee_filter_schema,
    LogFilterSchema, log_filter_schema,
    DepartmentFilterSchema, department_filter_schema
)

# Schémas pour l'intégration ZKTeco
from .zkteco_schema import (
    ZKTecoDeviceSchema, zkteco_device_schema, zkteco_device_list_schema,
    ZKTecomapSchema, zkteco_sync_schema, zkteco_user_map_schema
)

# Export des symboles principaux
__all__ = [
    # Schémas de base
    'BaseSchema', 'PaginatedSchema',
    
    # Authentification et utilisateurs
    'UserSchema', 'user_schema', 'user_list_schema', 'user_create_schema',
    'UserCreateSchema', 'LoginSchema', 'login_schema',
    'RefreshTokenSchema', 'refresh_token_schema',
    'ChangePasswordSchema', 'change_password_schema',
    'PasswordResetRequestSchema', 'password_reset_request_schema',
    'PasswordResetSchema', 'password_reset_schema',
    
    # Employés
    'EmployeeSchema', 'employee_schema', 'employee_list_schema',
    'employee_detail_schema', 'employee_create_schema', 'employee_update_schema',
    
    # Départements
    'DepartmentSchema', 'department_schema', 'department_list_schema',
    'department_tree_schema', 'department_create_schema', 'department_update_schema',
    
    # Logs de pointage
    'LogSchema', 'log_schema', 'log_list_schema', 'log_create_schema', 'log_update_schema',
    'CheckInOutSchema', 'check_in_out_schema',
    'BreakSchema', 'break_schema',
    
    # Rapports et exports
    'DateRangeSchema', 'date_range_schema',
    'AttendanceReportSchema', 'attendance_report_schema',
    'ExportDataSchema', 'export_data_schema',
    'EmployeeAttendanceStatsSchema', 'employee_attendance_stats_schema',
    
    # Filtrage et recherche
    'PaginationSchema', 'pagination_schema',
    'EmployeeFilterSchema', 'employee_filter_schema',
    'LogFilterSchema', 'log_filter_schema',
    'DepartmentFilterSchema', 'department_filter_schema',
    
    # Intégration ZKTeco
    'ZKTecoDeviceSchema', 'zkteco_device_schema', 'zkteco_device_list_schema',
    'ZKTecomapSchema', 'zkteco_sync_schema', 'zkteco_user_map_schema'
]
