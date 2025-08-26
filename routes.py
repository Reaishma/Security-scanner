from flask import render_template, request, jsonify, Response, stream_template
from app import app, db
from models import SecurityScan, Vulnerability, ScanMetrics, PolicyScan, PolicyViolation, PolicyMetrics
from security_scanner import SecurityScanner
from policy_engine import PolicyManager, PolicyType
from datetime import datetime, date
import json
import time

@app.route('/')
def dashboard():
    """Main security dashboard"""
    # Get recent scans
    recent_scans = SecurityScan.query.order_by(SecurityScan.started_at.desc()).limit(10).all()
    
    # Get vulnerability statistics
    total_vulns = Vulnerability.query.count()
    critical_vulns = Vulnerability.query.filter_by(severity='critical').count()
    high_vulns = Vulnerability.query.filter_by(severity='high').count()
    
    # Get scan statistics
    total_scans = SecurityScan.query.count()
    running_scans = SecurityScan.query.filter_by(status='running').count()
    completed_scans = SecurityScan.query.filter_by(status='completed').count()
    
    return render_template('dashboard.html',
                         recent_scans=recent_scans,
                         total_vulns=total_vulns,
                         critical_vulns=critical_vulns,
                         high_vulns=high_vulns,
                         total_scans=total_scans,
                         running_scans=running_scans,
                         completed_scans=completed_scans)

@app.route('/scans')
def scans():
    """Security scans management page"""
    scans = SecurityScan.query.order_by(SecurityScan.started_at.desc()).all()
    return render_template('scans.html', scans=scans)

@app.route('/vulnerabilities')
def vulnerabilities():
    """Vulnerabilities management page"""
    vulns = Vulnerability.query.order_by(Vulnerability.discovered_at.desc()).all()
    return render_template('vulnerabilities.html', vulnerabilities=vulns)

@app.route('/api/start_scan', methods=['POST'])
def start_scan():
    """Start a new security scan"""
    data = request.get_json()
    scan_type = data.get('scan_type', 'SAST')
    target = data.get('target', 'current_project')
    
    # Create new scan record
    scan = SecurityScan()
    scan.scan_type = scan_type
    scan.target = target
    scan.status = 'pending'
    db.session.add(scan)
    db.session.commit()
    
    # Start the scan asynchronously
    scanner = SecurityScanner()
    scanner.start_scan(scan.id, scan_type, target)
    
    return jsonify({'success': True, 'scan_id': scan.id})

@app.route('/api/scan_status/<int:scan_id>')
def scan_status(scan_id):
    """Get current status of a scan"""
    scan = SecurityScan.query.get_or_404(scan_id)
    return jsonify(scan.to_dict())

@app.route('/api/dashboard_data')
def dashboard_data():
    """API endpoint for dashboard data"""
    # Get running scans
    running_scans = SecurityScan.query.filter_by(status='running').all()
    
    # Get recent vulnerabilities
    recent_vulns = Vulnerability.query.order_by(Vulnerability.discovered_at.desc()).limit(5).all()
    
    # Get scan metrics for charts
    metrics = ScanMetrics.query.order_by(ScanMetrics.date.desc()).limit(30).all()
    
    return jsonify({
        'running_scans': [scan.to_dict() for scan in running_scans],
        'recent_vulnerabilities': [vuln.to_dict() for vuln in recent_vulns],
        'metrics': [{
            'date': metric.date.isoformat(),
            'total_scans': metric.total_scans,
            'total_vulnerabilities': metric.total_vulnerabilities,
            'critical_vulnerabilities': metric.critical_vulnerabilities
        } for metric in metrics]
    })

@app.route('/api/events')
def events():
    """Server-sent events for real-time updates"""
    def event_stream():
        try:
            with app.app_context():
                # Send initial connection confirmation
                yield f"data: {json.dumps({'type': 'connected', 'message': 'Real-time connection established'})}\n\n"
                
                count = 0
                max_updates = 50  # Limit to prevent infinite connections
                
                while count < max_updates:
                    try:
                        # Get latest scan updates
                        running_scans = SecurityScan.query.filter_by(status='running').all()
                        
                        # Send scan progress updates
                        if running_scans:
                            for scan in running_scans:
                                yield f"data: {json.dumps({'type': 'scan_progress', 'scan': scan.to_dict()})}\n\n"
                        
                        # Send periodic heartbeat
                        if count % 5 == 0:
                            yield f"data: {json.dumps({'type': 'heartbeat', 'timestamp': datetime.utcnow().isoformat()})}\n\n"
                        
                        count += 1
                        time.sleep(0.5)  # Faster updates
                        
                    except Exception as e:
                        app.logger.error(f"Error in event stream: {e}")
                        yield f"data: {json.dumps({'type': 'error', 'message': 'Connection error'})}\n\n"
                        break
                        
                # Send connection close message
                yield f"data: {json.dumps({'type': 'close', 'message': 'Connection closing - please reconnect'})}\n\n"
                
        except Exception as e:
            app.logger.error(f"Event stream error: {e}")
            yield f"data: {json.dumps({'type': 'error', 'message': 'Stream error'})}\n\n"
    
    response = Response(event_stream(), mimetype="text/event-stream")
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['Connection'] = 'keep-alive'
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

@app.route('/api/webhook/scan_complete', methods=['POST'])
def webhook_scan_complete():
    """Webhook endpoint for scan completion"""
    data = request.get_json()
    scan_id = data.get('scan_id')
    
    scan = SecurityScan.query.get(scan_id)
    if scan:
        scan.status = 'completed'
        scan.completed_at = datetime.utcnow()
        scan.results = json.dumps(data.get('results', {}))
        db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/vulnerability_stats')
def vulnerability_stats():
    """Get vulnerability statistics for charts"""
    stats = {
        'by_severity': {
            'critical': Vulnerability.query.filter_by(severity='critical').count(),
            'high': Vulnerability.query.filter_by(severity='high').count(),
            'medium': Vulnerability.query.filter_by(severity='medium').count(),
            'low': Vulnerability.query.filter_by(severity='low').count()
        },
        'by_type': {},
        'by_status': {
            'open': Vulnerability.query.filter_by(status='open').count(),
            'fixed': Vulnerability.query.filter_by(status='fixed').count(),
            'false_positive': Vulnerability.query.filter_by(status='false_positive').count()
        }
    }
    
    # Get vulnerability types
    vuln_types = db.session.query(Vulnerability.vulnerability_type, db.func.count(Vulnerability.id))\
        .group_by(Vulnerability.vulnerability_type).all()
    
    for vuln_type, count in vuln_types:
        stats['by_type'][vuln_type] = count
    
    return jsonify(stats)

# Initialize policy manager
policy_manager = PolicyManager()

@app.route('/api/policy/validate', methods=['POST'])
def validate_policies():
    """Validate infrastructure or Kubernetes resources against policies"""
    try:
        data = request.get_json()
        validation_type = data.get('type')  # 'terraform' or 'kubernetes'
        
        if validation_type == 'terraform':
            plan_file = data.get('plan_file')
            if not plan_file:
                return jsonify({'error': 'Terraform plan file required'}), 400
            
            results = policy_manager.evaluate_infrastructure_policies(plan_file)
            
        elif validation_type == 'kubernetes':
            resources = data.get('resources', [])
            if not resources:
                return jsonify({'error': 'Kubernetes resources required'}), 400
            
            results = policy_manager.evaluate_kubernetes_policies(resources)
            
        else:
            return jsonify({'error': 'Invalid validation type. Use "terraform" or "kubernetes"'}), 400
        
        # Store results in database
        for result in results:
            policy_scan = PolicyScan()
            policy_scan.scan_type = result.policy_type.value
            policy_scan.policy_name = result.policy_name
            policy_scan.target_type = validation_type
            policy_scan.target_identifier = data.get('target', 'unknown')
            policy_scan.status = 'completed'
            policy_scan.result = result.result.value
            policy_scan.execution_time = result.execution_time
            policy_scan.violations_count = len(result.violations)
            policy_scan.set_metadata(result.metadata)
            policy_scan.completed_at = datetime.utcnow()
            
            db.session.add(policy_scan)
            db.session.flush()  # Get the ID
            
            # Store violations
            for violation in result.violations:
                policy_violation = PolicyViolation()
                policy_violation.policy_scan_id = policy_scan.id
                policy_violation.rule_name = violation.rule_name
                policy_violation.message = violation.message
                policy_violation.severity = violation.severity
                policy_violation.resource_type = violation.resource_type
                policy_violation.resource_name = violation.resource_name
                
                db.session.add(policy_violation)
        
        db.session.commit()
        
        # Generate report
        report = policy_manager.generate_policy_report(results)
        
        return jsonify({
            'status': 'completed',
            'validation_type': validation_type,
            'report': report
        })
        
    except Exception as e:
        app.logger.error(f"Policy validation error: {e}")
        return jsonify({'error': 'Policy validation failed'}), 500

@app.route('/api/policy/scans')
def get_policy_scans():
    """Get policy scan history"""
    try:
        scans = PolicyScan.query.order_by(PolicyScan.started_at.desc()).limit(50).all()
        return jsonify({
            'scans': [scan.to_dict() for scan in scans]
        })
    except Exception as e:
        app.logger.error(f"Error fetching policy scans: {e}")
        return jsonify({'error': 'Failed to fetch policy scans'}), 500

@app.route('/api/policy/violations')
def get_policy_violations():
    """Get policy violations"""
    try:
        status_filter = request.args.get('status', 'open')
        severity_filter = request.args.get('severity')
        
        query = PolicyViolation.query
        
        if status_filter:
            query = query.filter(PolicyViolation.status == status_filter)
        
        if severity_filter:
            query = query.filter(PolicyViolation.severity == severity_filter)
        
        violations = query.order_by(PolicyViolation.discovered_at.desc()).limit(100).all()
        
        return jsonify({
            'violations': [violation.to_dict() for violation in violations]
        })
    except Exception as e:
        app.logger.error(f"Error fetching policy violations: {e}")
        return jsonify({'error': 'Failed to fetch policy violations'}), 500

@app.route('/api/policy/metrics')
def get_policy_metrics():
    """Get policy compliance metrics"""
    try:
        # Get recent metrics
        metrics = PolicyMetrics.query.order_by(PolicyMetrics.date.desc()).limit(30).all()
        
        # Calculate current compliance score
        recent_scans = PolicyScan.query.filter(
            PolicyScan.started_at >= datetime.utcnow().replace(hour=0, minute=0, second=0)
        ).all()
        
        total_scans = len(recent_scans)
        passed_scans = len([s for s in recent_scans if s.result == 'pass'])
        
        current_compliance = (passed_scans / total_scans * 100) if total_scans > 0 else 0
        
        # Group violations by severity
        recent_violations = PolicyViolation.query.filter(
            PolicyViolation.discovered_at >= datetime.utcnow().replace(hour=0, minute=0, second=0)
        ).all()
        
        violations_by_severity = {}
        for violation in recent_violations:
            severity = violation.severity
            violations_by_severity[severity] = violations_by_severity.get(severity, 0) + 1
        
        return jsonify({
            'current_compliance': current_compliance,
            'total_scans_today': total_scans,
            'violations_by_severity': violations_by_severity,
            'historical_metrics': [metric.to_dict() for metric in metrics]
        })
        
    except Exception as e:
        app.logger.error(f"Error fetching policy metrics: {e}")
        return jsonify({'error': 'Failed to fetch policy metrics'}), 500

@app.route('/policies')
def policies():
    """Policy management page"""
    return render_template('policies.html')
