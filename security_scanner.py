import threading
import time
import random
from datetime import datetime
from app import db
from models import SecurityScan, Vulnerability, ScanMetrics
import json
import os

class SecurityScanner:
    def __init__(self):
        self.scan_tools = {
            'SAST': ['SonarQube', 'Veracode', 'Checkmarx'],
            'DAST': ['Acunetix', 'OWASP ZAP', 'Burp Suite'],
            'IaC': ['Checkov', 'Terrascan', 'TFSec']
        }
        
    def start_scan(self, scan_id, scan_type, target):
        """Start a security scan in a background thread"""
        thread = threading.Thread(target=self._run_scan, args=(scan_id, scan_type, target))
        thread.daemon = True
        thread.start()
        
    def _run_scan(self, scan_id, scan_type, target):
        """Run the actual security scan"""
        with db.app.app_context():
            scan = SecurityScan.query.get(scan_id)
            if not scan:
                return
                
            try:
                # Update scan status
                scan.status = 'running'
                scan.total_files = random.randint(50, 200)
                db.session.commit()
                
                # Simulate scanning process
                self._simulate_scan_progress(scan, scan_type)
                
                # Generate vulnerabilities
                self._generate_vulnerabilities(scan, scan_type)
                
                # Complete scan
                scan.status = 'completed'
                scan.completed_at = datetime.utcnow()
                scan.progress = 100
                db.session.commit()
                
            except Exception as e:
                scan.status = 'failed'
                scan.results = json.dumps({'error': str(e)})
                db.session.commit()
                
    def _simulate_scan_progress(self, scan, scan_type):
        """Simulate scanning progress with realistic timing"""
        total_files = scan.total_files
        scan_duration = random.randint(30, 120)  # 30-120 seconds
        
        for i in range(total_files):
            # Simulate processing each file
            time.sleep(scan_duration / total_files)
            
            scan.scanned_files = i + 1
            scan.progress = int((i + 1) / total_files * 100)
            
            # Occasionally find vulnerabilities during scan
            if random.random() < 0.1:  # 10% chance per file
                scan.vulnerabilities_found += 1
                
            db.session.commit()
            
    def _generate_vulnerabilities(self, scan, scan_type):
        """Generate realistic vulnerabilities based on scan type"""
        vulnerability_templates = {
            'SAST': [
                {
                    'type': 'SQL Injection',
                    'severity': 'critical',
                    'cwe': 'CWE-89',
                    'description': 'Potential SQL injection vulnerability detected in database query'
                },
                {
                    'type': 'Cross-Site Scripting (XSS)',
                    'severity': 'high',
                    'cwe': 'CWE-79',
                    'description': 'Reflected XSS vulnerability in user input handling'
                },
                {
                    'type': 'Hardcoded Credentials',
                    'severity': 'high',
                    'cwe': 'CWE-798',
                    'description': 'Hardcoded password or API key found in source code'
                },
                {
                    'type': 'Buffer Overflow',
                    'severity': 'critical',
                    'cwe': 'CWE-120',
                    'description': 'Potential buffer overflow in memory allocation'
                }
            ],
            'DAST': [
                {
                    'type': 'Unencrypted Data Transmission',
                    'severity': 'medium',
                    'cwe': 'CWE-319',
                    'description': 'Sensitive data transmitted over unencrypted connection'
                },
                {
                    'type': 'Missing Security Headers',
                    'severity': 'low',
                    'cwe': 'CWE-693',
                    'description': 'Missing security headers in HTTP response'
                },
                {
                    'type': 'Directory Traversal',
                    'severity': 'high',
                    'cwe': 'CWE-22',
                    'description': 'Path traversal vulnerability allows access to restricted files'
                }
            ],
            'IaC': [
                {
                    'type': 'Insecure S3 Bucket Configuration',
                    'severity': 'high',
                    'cwe': 'CWE-732',
                    'description': 'S3 bucket configured with public read/write access'
                },
                {
                    'type': 'Missing Encryption',
                    'severity': 'medium',
                    'cwe': 'CWE-311',
                    'description': 'Database or storage not configured with encryption at rest'
                },
                {
                    'type': 'Overly Permissive IAM Policy',
                    'severity': 'medium',
                    'cwe': 'CWE-269',
                    'description': 'IAM policy grants excessive permissions'
                }
            ]
        }
        
        templates = vulnerability_templates.get(scan_type, [])
        num_vulns = random.randint(0, min(5, len(templates)))
        
        for i in range(num_vulns):
            template = random.choice(templates)
            
            vulnerability = Vulnerability()
            vulnerability.scan_id = scan.id
            vulnerability.severity = template['severity']
            vulnerability.vulnerability_type = template['type']
            vulnerability.description = template['description']
            vulnerability.file_path = f"src/main/{random.choice(['java', 'python', 'js'])}/component_{random.randint(1, 20)}.{random.choice(['py', 'js', 'java'])}"
            vulnerability.line_number = random.randint(1, 500)
            vulnerability.cwe_id = template['cwe']
            vulnerability.cvss_score = self._calculate_cvss_score(template['severity'])
            vulnerability.remediation = self._get_remediation(template['type'])
            
            db.session.add(vulnerability)
            
        db.session.commit()
        
    def _calculate_cvss_score(self, severity):
        """Calculate CVSS score based on severity"""
        scores = {
            'critical': random.uniform(9.0, 10.0),
            'high': random.uniform(7.0, 8.9),
            'medium': random.uniform(4.0, 6.9),
            'low': random.uniform(0.1, 3.9)
        }
        return round(scores.get(severity, 5.0), 1)
        
    def _get_remediation(self, vuln_type):
        """Get remediation advice for vulnerability type"""
        remediations = {
            'SQL Injection': 'Use parameterized queries or prepared statements. Validate and sanitize all user inputs.',
            'Cross-Site Scripting (XSS)': 'Implement proper input validation and output encoding. Use Content Security Policy (CSP).',
            'Hardcoded Credentials': 'Move credentials to environment variables or secure credential management system.',
            'Buffer Overflow': 'Use safe string manipulation functions and implement proper bounds checking.',
            'Unencrypted Data Transmission': 'Implement HTTPS/TLS for all data transmission. Use secure communication protocols.',
            'Missing Security Headers': 'Add security headers like X-Frame-Options, X-Content-Type-Options, and X-XSS-Protection.',
            'Directory Traversal': 'Implement proper input validation and use whitelisting for file access.',
            'Insecure S3 Bucket Configuration': 'Review and restrict S3 bucket permissions. Enable bucket policies and ACLs.',
            'Missing Encryption': 'Enable encryption at rest for databases and storage. Use strong encryption algorithms.',
            'Overly Permissive IAM Policy': 'Apply principle of least privilege. Review and restrict IAM permissions.'
        }
        return remediations.get(vuln_type, 'Review and apply security best practices.')
        
    def run_scheduled_scan(self):
        """Run scheduled security scan"""
        with db.app.app_context():
            # Create a scheduled scan
            scan = SecurityScan()
            scan.scan_type = 'SAST'
            scan.target = 'scheduled_scan'
            scan.status = 'pending'
            db.session.add(scan)
            db.session.commit()
            
            self._run_scan(scan.id, 'SAST', 'scheduled_scan')
