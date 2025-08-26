from app import db
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import json

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class SecurityScan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_type = db.Column(db.String(50), nullable=False)  # SAST, DAST, IaC
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    target = db.Column(db.String(255), nullable=False)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    progress = db.Column(db.Integer, default=0)
    total_files = db.Column(db.Integer, default=0)
    scanned_files = db.Column(db.Integer, default=0)
    vulnerabilities_found = db.Column(db.Integer, default=0)
    scan_config = db.Column(db.Text)
    results = db.Column(db.Text)
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_type': self.scan_type,
            'status': self.status,
            'target': self.target,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'progress': self.progress,
            'total_files': self.total_files,
            'scanned_files': self.scanned_files,
            'vulnerabilities_found': self.vulnerabilities_found
        }

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('security_scan.id'), nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # critical, high, medium, low
    vulnerability_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    file_path = db.Column(db.String(500))
    line_number = db.Column(db.Integer)
    cwe_id = db.Column(db.String(20))
    cvss_score = db.Column(db.Float)
    status = db.Column(db.String(20), default='open')  # open, fixed, false_positive, ignored
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    remediation = db.Column(db.Text)
    
    scan = db.relationship('SecurityScan', backref=db.backref('vulnerabilities', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'severity': self.severity,
            'vulnerability_type': self.vulnerability_type,
            'description': self.description,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'cwe_id': self.cwe_id,
            'cvss_score': self.cvss_score,
            'status': self.status,
            'discovered_at': self.discovered_at.isoformat() if self.discovered_at else None
        }

class ScanMetrics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    total_scans = db.Column(db.Integer, default=0)
    successful_scans = db.Column(db.Integer, default=0)
    failed_scans = db.Column(db.Integer, default=0)
    total_vulnerabilities = db.Column(db.Integer, default=0)
    critical_vulnerabilities = db.Column(db.Integer, default=0)
    high_vulnerabilities = db.Column(db.Integer, default=0)
    medium_vulnerabilities = db.Column(db.Integer, default=0)
    low_vulnerabilities = db.Column(db.Integer, default=0)
    avg_scan_duration = db.Column(db.Float, default=0.0)

class PolicyScan(db.Model):
    """Policy scan results for infrastructure and Kubernetes resources"""
    id = db.Column(db.Integer, primary_key=True)
    scan_type = db.Column(db.String(20), nullable=False)  # sentinel, opa
    policy_name = db.Column(db.String(100), nullable=False)
    target_type = db.Column(db.String(50), nullable=False)  # terraform, kubernetes
    target_identifier = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    result = db.Column(db.String(20))  # pass, fail, error
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    execution_time = db.Column(db.Float, default=0.0)
    violations_count = db.Column(db.Integer, default=0)
    scan_metadata = db.Column(db.Text)  # JSON metadata
    
    def set_metadata(self, data):
        self.scan_metadata = json.dumps(data) if data else None
    
    def get_metadata(self):
        return json.loads(self.scan_metadata) if self.scan_metadata else {}
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_type': self.scan_type,
            'policy_name': self.policy_name,
            'target_type': self.target_type,
            'target_identifier': self.target_identifier,
            'status': self.status,
            'result': self.result,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'execution_time': self.execution_time,
            'violations_count': self.violations_count,
            'scan_metadata': self.get_metadata()
        }

class PolicyViolation(db.Model):
    """Individual policy violations found during scans"""
    id = db.Column(db.Integer, primary_key=True)
    policy_scan_id = db.Column(db.Integer, db.ForeignKey('policy_scan.id'), nullable=False)
    rule_name = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # critical, high, medium, low, error
    resource_type = db.Column(db.String(100))
    resource_name = db.Column(db.String(255))
    resource_location = db.Column(db.String(500))  # file path, line number, etc.
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='open')  # open, resolved, suppressed
    
    policy_scan = db.relationship('PolicyScan', backref=db.backref('violations', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'policy_scan_id': self.policy_scan_id,
            'rule_name': self.rule_name,
            'message': self.message,
            'severity': self.severity,
            'resource_type': self.resource_type,
            'resource_name': self.resource_name,
            'resource_location': self.resource_location,
            'discovered_at': self.discovered_at.isoformat() if self.discovered_at else None,
            'status': self.status
        }

class PolicyMetrics(db.Model):
    """Policy compliance metrics and trends"""
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    policy_type = db.Column(db.String(20), nullable=False)  # sentinel, opa
    total_policies = db.Column(db.Integer, default=0)
    passed_policies = db.Column(db.Integer, default=0)
    failed_policies = db.Column(db.Integer, default=0)
    error_policies = db.Column(db.Integer, default=0)
    total_violations = db.Column(db.Integer, default=0)
    critical_violations = db.Column(db.Integer, default=0)
    high_violations = db.Column(db.Integer, default=0)
    medium_violations = db.Column(db.Integer, default=0)
    low_violations = db.Column(db.Integer, default=0)
    compliance_score = db.Column(db.Float, default=0.0)  # Percentage
    avg_execution_time = db.Column(db.Float, default=0.0)
    
    def to_dict(self):
        return {
            'id': self.id,
            'date': self.date.isoformat() if self.date else None,
            'policy_type': self.policy_type,
            'total_policies': self.total_policies,
            'passed_policies': self.passed_policies,
            'failed_policies': self.failed_policies,
            'error_policies': self.error_policies,
            'total_violations': self.total_violations,
            'critical_violations': self.critical_violations,
            'high_violations': self.high_violations,
            'medium_violations': self.medium_violations,
            'low_violations': self.low_violations,
            'compliance_score': self.compliance_score,
            'avg_execution_time': self.avg_execution_time
        }
