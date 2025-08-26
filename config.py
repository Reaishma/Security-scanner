"""
Configuration settings for Security Scanner Dashboard
Handles environment-specific settings and security configurations
"""

import os
import logging
from datetime import timedelta
from typing import Dict, Any, Optional


class Config:
    """Base configuration class"""
    
    # Basic Flask settings
    SECRET_KEY = os.environ.get('SESSION_SECRET') or 'dev-secret-key-change-in-production'
    
    # Database configuration
    DATABASE_URL = os.environ.get('DATABASE_URL') or 'sqlite:///security_scanner.db'
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 300,
        'pool_pre_ping': True,
        'pool_size': 10,
        'max_overflow': 20
    }
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security settings
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    
    # Security scanning configuration
    SECURITY_SCANNER_CONFIG = {
        'scan_timeout': 3600,  # 1 hour
        'max_concurrent_scans': 5,
        'scan_result_retention_days': 90,
        'vulnerability_severity_levels': ['critical', 'high', 'medium', 'low'],
        'default_scan_types': ['SAST', 'DAST', 'IaC']
    }
    
    # Tool configurations
    SAST_TOOLS = {
        'sonarqube': {
            'enabled': os.environ.get('SONARQUBE_ENABLED', 'true').lower() == 'true',
            'url': os.environ.get('SONAR_HOST_URL', 'http://localhost:9000'),
            'token': os.environ.get('SONAR_TOKEN', ''),
            'project_key': os.environ.get('SONAR_PROJECT_KEY', 'security-scanner-dashboard'),
            'timeout': 1800
        },
        'veracode': {
            'enabled': os.environ.get('VERACODE_ENABLED', 'false').lower() == 'true',
            'api_id': os.environ.get('VERACODE_API_ID', ''),
            'api_key': os.environ.get('VERACODE_API_KEY', ''),
            'app_name': 'Security Scanner Dashboard',
            'timeout': 3600
        },
        'checkmarx': {
            'enabled': os.environ.get('CHECKMARX_ENABLED', 'false').lower() == 'true',
            'url': os.environ.get('CHECKMARX_URL', ''),
            'username': os.environ.get('CHECKMARX_USERNAME', ''),
            'password': os.environ.get('CHECKMARX_PASSWORD', ''),
            'client_secret': os.environ.get('CHECKMARX_CLIENT_SECRET', ''),
            'team': '/CxServer/SP/Company/Security Team',
            'preset': 'Checkmarx Default',
            'timeout': 3600
        },
        'semgrep': {
            'enabled': os.environ.get('SEMGREP_ENABLED', 'true').lower() == 'true',
            'token': os.environ.get('SEMGREP_APP_TOKEN', ''),
            'rules': ['p/security-audit', 'p/secrets', 'p/python', 'p/flask'],
            'timeout': 1200
        },
        'bandit': {
            'enabled': True,
            'config_file': '.bandit',
            'confidence_level': 'HIGH',
            'severity_level': 'LOW'
        }
    }
    
    DAST_TOOLS = {
        'acunetix': {
            'enabled': os.environ.get('ACUNETIX_ENABLED', 'false').lower() == 'true',
            'url': os.environ.get('ACUNETIX_URL', ''),
            'api_key': os.environ.get('ACUNETIX_API_KEY', ''),
            'timeout': 7200
        },
        'owasp_zap': {
            'enabled': os.environ.get('OWASP_ZAP_ENABLED', 'true').lower() == 'true',
            'api_key': os.environ.get('ZAP_API_KEY', ''),
            'proxy_host': os.environ.get('ZAP_PROXY_HOST', 'localhost'),
            'proxy_port': int(os.environ.get('ZAP_PROXY_PORT', '8080')),
            'timeout': 3600
        },
        'burp_suite': {
            'enabled': os.environ.get('BURP_ENABLED', 'false').lower() == 'true',
            'api_key': os.environ.get('BURP_API_KEY', ''),
            'api_url': os.environ.get('BURP_API_URL', ''),
            'timeout': 3600
        }
    }
    
    IAC_TOOLS = {
        'checkov': {
            'enabled': os.environ.get('CHECKOV_ENABLED', 'true').lower() == 'true',
            'api_key': os.environ.get('CHECKOV_API_KEY', ''),
            'frameworks': ['terraform', 'cloudformation', 'kubernetes'],
            'timeout': 600
        },
        'terrascan': {
            'enabled': os.environ.get('TERRASCAN_ENABLED', 'true').lower() == 'true',
            'policy_type': 'aws',
            'timeout': 600
        },
        'tfsec': {
            'enabled': True,
            'exclude_passed': True,
            'timeout': 300
        }
    }
    
    # Notification settings
    NOTIFICATIONS = {
        'slack': {
            'enabled': os.environ.get('SLACK_ENABLED', 'false').lower() == 'true',
            'webhook_url': os.environ.get('SLACK_WEBHOOK_URL', ''),
            'channel': os.environ.get('SLACK_CHANNEL', '#security-alerts'),
            'mention_users': os.environ.get('SLACK_MENTION_USERS', '@security-team').split(',')
        },
        'email': {
            'enabled': os.environ.get('EMAIL_ENABLED', 'false').lower() == 'true',
            'smtp_server': os.environ.get('SMTP_SERVER', 'smtp.gmail.com'),
            'smtp_port': int(os.environ.get('SMTP_PORT', '587')),
            'username': os.environ.get('EMAIL_USERNAME', ''),
            'password': os.environ.get('EMAIL_PASSWORD', ''),
            'from_address': os.environ.get('EMAIL_FROM', 'security@company.com'),
            'recipients': os.environ.get('SECURITY_EMAIL', 'security@company.com').split(',')
        },
        'teams': {
            'enabled': os.environ.get('TEAMS_ENABLED', 'false').lower() == 'true',
            'webhook_url': os.environ.get('TEAMS_WEBHOOK_URL', '')
        }
    }
    
    # Cloud provider settings
    AWS_CONFIG = {
        'region': os.environ.get('AWS_REGION', 'us-east-1'),
        'access_key_id': os.environ.get('AWS_ACCESS_KEY_ID', ''),
        'secret_access_key': os.environ.get('AWS_SECRET_ACCESS_KEY', ''),
        'kms_key_id': os.environ.get('AWS_KMS_KEY_ID', ''),
        's3_bucket': os.environ.get('AWS_S3_BUCKET', ''),
        'secrets_manager_enabled': os.environ.get('AWS_SECRETS_MANAGER_ENABLED', 'false').lower() == 'true'
    }
    
    AZURE_CONFIG = {
        'tenant_id': os.environ.get('AZURE_TENANT_ID', ''),
        'client_id': os.environ.get('AZURE_CLIENT_ID', ''),
        'client_secret': os.environ.get('AZURE_CLIENT_SECRET', ''),
        'subscription_id': os.environ.get('AZURE_SUBSCRIPTION_ID', ''),
        'key_vault_url': os.environ.get('AZURE_KEY_VAULT_URL', ''),
        'resource_group': os.environ.get('AZURE_RESOURCE_GROUP', '')
    }
    
    GCP_CONFIG = {
        'project_id': os.environ.get('GCP_PROJECT_ID', ''),
        'service_account_path': os.environ.get('GCP_SERVICE_ACCOUNT_PATH', ''),
        'kms_key_name': os.environ.get('GCP_KMS_KEY_NAME', ''),
        'secret_manager_enabled': os.environ.get('GCP_SECRET_MANAGER_ENABLED', 'false').lower() == 'true'
    }
    
    # HSM and Key Management
    HSM_CONFIG = {
        'enabled': os.environ.get('HSM_ENABLED', 'false').lower() == 'true',
        'provider': os.environ.get('HSM_PROVIDER', 'aws'),  # aws, azure, gcp, thales
        'partition_label': os.environ.get('HSM_PARTITION_LABEL', ''),
        'partition_password': os.environ.get('HSM_PARTITION_PASSWORD', ''),
        'key_label': os.environ.get('HSM_KEY_LABEL', 'security-scanner-key')
    }
    
    # Compliance settings
    COMPLIANCE_FRAMEWORKS = {
        'pci_dss': {
            'enabled': os.environ.get('PCI_DSS_ENABLED', 'true').lower() == 'true',
            'requirements': [
                '6.5.1', '6.5.2', '6.5.3', '6.5.4', '6.5.5',
                '6.5.6', '6.5.7', '6.5.8', '6.5.9', '6.5.10'
            ]
        },
        'soc2': {
            'enabled': os.environ.get('SOC2_ENABLED', 'true').lower() == 'true',
            'trust_criteria': ['security', 'availability', 'confidentiality']
        },
        'gdpr': {
            'enabled': os.environ.get('GDPR_ENABLED', 'true').lower() == 'true',
            'data_retention_days': 365,
            'anonymization_enabled': True
        },
        'iso_27001': {
            'enabled': os.environ.get('ISO27001_ENABLED', 'true').lower() == 'true',
            'controls': ['A.14.2.1', 'A.14.2.5', 'A.14.2.8']
        },
        'nist': {
            'enabled': os.environ.get('NIST_ENABLED', 'true').lower() == 'true',
            'framework_version': '1.1',
            'categories': ['identify', 'protect', 'detect', 'respond', 'recover']
        }
    }
    
    # Real-time updates configuration
    REALTIME_CONFIG = {
        'enabled': True,
        'server_sent_events': True,
        'update_interval': 2,  # seconds
        'max_connections': 100,
        'heartbeat_interval': 30
    }
    
    # API rate limiting
    RATE_LIMITING = {
        'enabled': True,
        'default_limits': ['100 per hour', '1000 per day'],
        'scan_limits': ['10 per hour', '50 per day'],
        'api_limits': ['1000 per hour', '10000 per day']
    }
    
    # Logging configuration
    LOGGING_CONFIG = {
        'level': os.environ.get('LOG_LEVEL', 'INFO'),
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'file_path': os.environ.get('LOG_FILE_PATH', 'logs/security_scanner.log'),
        'max_bytes': 10485760,  # 10MB
        'backup_count': 5,
        'security_events_log': 'logs/security_events.log'
    }
    
    # Webhook endpoints
    WEBHOOK_ENDPOINTS = {
        'scan_complete': '/api/webhook/scan_complete',
        'vulnerability_found': '/api/webhook/vulnerability_found',
        'scan_failed': '/api/webhook/scan_failed',
        'compliance_violation': '/api/webhook/compliance_violation'
    }
    
    # Feature flags
    FEATURES = {
        'advanced_analytics': os.environ.get('FEATURE_ANALYTICS', 'true').lower() == 'true',
        'vulnerability_trending': os.environ.get('FEATURE_TRENDING', 'true').lower() == 'true',
        'custom_rules': os.environ.get('FEATURE_CUSTOM_RULES', 'false').lower() == 'true',
        'api_integration': os.environ.get('FEATURE_API_INTEGRATION', 'true').lower() == 'true',
        'sso_integration': os.environ.get('FEATURE_SSO', 'false').lower() == 'true'
    }

    @staticmethod
    def init_app(app):
        """Initialize application with configuration"""
        pass


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    SESSION_COOKIE_SECURE = False
    
    # Override database for development
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or 'sqlite:///dev_security_scanner.db'
    
    # Enable all tools for development
    SAST_TOOLS = {**Config.SAST_TOOLS}
    for tool in SAST_TOOLS.values():
        if isinstance(tool, dict):
            tool['enabled'] = True
    
    # Relaxed security for development
    WTF_CSRF_ENABLED = False
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        
        # Development logging
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    
    # In-memory database for testing
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Disable external integrations for testing
    SAST_TOOLS = {tool: {**config, 'enabled': False} for tool, config in Config.SAST_TOOLS.items()}
    DAST_TOOLS = {tool: {**config, 'enabled': False} for tool, config in Config.DAST_TOOLS.items()}
    IAC_TOOLS = {tool: {**config, 'enabled': False} for tool, config in Config.IAC_TOOLS.items()}
    
    # Disable notifications for testing
    NOTIFICATIONS = {service: {**config, 'enabled': False} for service, config in Config.NOTIFICATIONS.items()}
    
    # Disable CSRF for testing
    WTF_CSRF_ENABLED = False
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        
        # Testing logging
        logging.basicConfig(level=logging.WARNING)


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    
    # Enhanced security for production
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    
    # Production database with connection pooling
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 300,
        'pool_pre_ping': True,
        'pool_size': 20,
        'max_overflow': 40,
        'pool_timeout': 30
    }
    
    # Strict rate limiting for production
    RATE_LIMITING = {
        'enabled': True,
        'default_limits': ['50 per hour', '500 per day'],
        'scan_limits': ['5 per hour', '25 per day'],
        'api_limits': ['500 per hour', '5000 per day']
    }
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        
        # Production logging with file rotation
        import logging.handlers
        
        file_handler = logging.handlers.RotatingFileHandler(
            cls.LOGGING_CONFIG['file_path'],
            maxBytes=cls.LOGGING_CONFIG['max_bytes'],
            backupCount=cls.LOGGING_CONFIG['backup_count']
        )
        file_handler.setFormatter(logging.Formatter(cls.LOGGING_CONFIG['format']))
        file_handler.setLevel(getattr(logging, cls.LOGGING_CONFIG['level']))
        
        app.logger.addHandler(file_handler)
        app.logger.setLevel(getattr(logging, cls.LOGGING_CONFIG['level']))


class DockerConfig(ProductionConfig):
    """Docker container configuration"""
    
    @classmethod
    def init_app(cls, app):
        ProductionConfig.init_app(app)
        
        # Container-specific logging to stdout
        import logging
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.INFO)
        app.logger.addHandler(stream_handler)


# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'docker': DockerConfig,
    'default': DevelopmentConfig
}


def get_config() -> Config:
    """Get configuration based on environment"""
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])


# Utility functions for configuration management
def validate_config(config_obj: Config) -> Dict[str, Any]:
    """Validate configuration settings"""
    issues = []
    
    # Check required settings
    if not config_obj.SECRET_KEY or config_obj.SECRET_KEY == 'dev-secret-key-change-in-production':
        issues.append("SECRET_KEY should be set to a secure random value")
    
    # Check database configuration
    if not config_obj.SQLALCHEMY_DATABASE_URI:
        issues.append("Database URI must be configured")
    
    # Check security tool configurations
    enabled_sast_tools = [tool for tool, config in config_obj.SAST_TOOLS.items() if config.get('enabled')]
    if not enabled_sast_tools:
        issues.append("At least one SAST tool should be enabled")
    
    # Check notification configurations
    enabled_notifications = [service for service, config in config_obj.NOTIFICATIONS.items() if config.get('enabled')]
    if not enabled_notifications:
        issues.append("At least one notification service should be enabled for production")
    
    return {
        'valid': len(issues) == 0,
        'issues': issues
    }


def get_tool_config(tool_type: str, tool_name: str) -> Optional[Dict[str, Any]]:
    """Get configuration for a specific security tool"""
    config_obj = get_config()
    
    tool_configs = {
        'SAST': config_obj.SAST_TOOLS,
        'DAST': config_obj.DAST_TOOLS,
        'IaC': config_obj.IAC_TOOLS
    }
    
    return tool_configs.get(tool_type, {}).get(tool_name)


def is_tool_enabled(tool_type: str, tool_name: str) -> bool:
    """Check if a specific security tool is enabled"""
    tool_config = get_tool_config(tool_type, tool_name)
    return tool_config.get('enabled', False) if tool_config else False
