# Security Scanner Application

A comprehensive Flask-based security scanning web application with real-time security scanning and vulnerability monitoring capabilities. This application  featuring multi-tool security scanning (SAST, DAST,Infrastructure as Code scanning), enabling security teams to manage and track vulnerabilities across their applications. The system features real-time updates, automated scanning capabilities, and integration with enterprise security tools like SonarQube, Acunetix, Veracode, and OWASP ZAP and also  build, deployment using GitHub CI/CD pipeline, cloud infrastructure.


![security scanner](https://github.com/Reaishma/Security-scanner/blob/main/Screenshot_20250904-111648_1.jpg)

# 🚀 Live Website 

**View Webpage on** https://reaishma.github.io/Security-scanner/

## Developer 🧑‍💻 

**Reaishma N**

## System Architecture

### Frontend Architecture
- **Template Engine**: Jinja2 templates with a modular base template system
- **UI Framework**: Bootstrap 5 with dark theme support for modern, responsive design
- **Interactive Components**: Chart.js for data visualization, Feather Icons for consistent iconography
- **Real-time Updates**: Server-Sent Events (SSE) with fallback polling mechanism for live scan progress and vulnerability updates
- **Progressive Enhancement**: JavaScript modules for dashboard analytics, real-time updates, and interactive scanning controls

### Backend Architecture
- **Web Framework**: Flask with SQLAlchemy ORM for database operations
- **Database Design**: Relational model with entities for Users, SecurityScans, Vulnerabilities, and ScanMetrics
- **Background Processing**: APScheduler for periodic tasks and threading for long-running scan operations
- **Security Integration Layer**: Centralized SecurityScanner class that orchestrates multiple scanning tools
- **Configuration Management**: Environment-based configuration with support for development and production settings

### Data Storage Solutions
- **Primary Database**: SQLite for development with PostgreSQL production readiness
- **Schema Design**: Normalized structure with proper foreign key relationships between scans and vulnerabilities
- **Connection Management**: Connection pooling with automatic reconnection and health checks
- **Data Retention**: Configurable retention policies for scan results and vulnerability data

### Authentication and Authorization
- **User Management**: Flask-Login integration with role-based access control
- **Security Hardening**: CSRF protection, secure session management, and password hashing
- **Session Configuration**: HTTP-only cookies with secure flags and configurable lifetime
- **Admin Controls**: Administrative interface for user management and system configuration

## Features

### Security Scanning Capabilities

![security scanning](https://github.com/Reaishma/Security-scanner/blob/main/Screenshot_20250904-111637_1.jpg)

- **Static Application Security Testing (SAST)** - Code analysis for security vulnerabilities
- **Dynamic Application Security Testing (DAST)** - Runtime security testing
- **Infrastructure as Code (IaC) Scanning** - Terraform, CloudFormation security analysis
- **Real-time Scan Progress** - Live updates with Server-Sent Events
- **Vulnerability Tracking** - Comprehensive vulnerability management with severity classification

### Tool Integrations
- **SonarQube** - Code quality and security analysis
- **Veracode** - Static and dynamic security testing
- **Checkmarx** - Static application security testing
- **Acunetix** - Web application vulnerability scanner
- **OWASP ZAP** - Security testing proxy
- **Burp Suite** - Web application security testing
- **Checkov** - Infrastructure as Code security scanner
- **Terrascan** - Infrastructure as Code security analysis
- **TFSec** - Terraform security scanner
- **Configuration Files**: Tool-specific configuration files (acunetix-config.json, veracode.json) for scan parameters and policies


### Real-time Features

![Vulnerability](https://github.com/Reaishma/Security-scanner/blob/main/Screenshot_20250904-111654_1.jpg)

- **Live Vulnerability Monitoring** - Real-time vulnerability discovery and tracking
- **Interactive Charts** - Vulnerability trends and severity distribution
- **Automated Scanning** - Scheduled security scans with APScheduler
- **Progressive Web App** - Responsive design with offline capabilities



## Quick Start

### Prerequisites
- Python 3.9+
- PostgreSQL database (or SQLite for development)
- Environment variables for API keys and secrets

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd security-scanner
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**
   ```bash
   export DATABASE_URL="postgresql://user:password@localhost/securitydb"
   export SESSION_SECRET="your-secret-key-here"
   export SONARQUBE_TOKEN="your-sonarqube-token"
   export VERACODE_API_ID="your-veracode-api-id"
   export VERACODE_API_KEY="your-veracode-api-key"
   ```

4. **Initialize the database**
   ```bash
   python -c "from app import app, db; app.app_context().push(); db.create_all()"
   ```

5. **Run the application**
   ```bash
   python main.py
   ```

The application will be available at `http://localhost:5000`

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DATABASE_URL` | PostgreSQL connection string | Yes |
| `SESSION_SECRET` | Flask session secret key | Yes |
| `SONARQUBE_URL` | SonarQube server URL | No |
| `SONARQUBE_TOKEN` | SonarQube authentication token | No |
| `VERACODE_API_ID` | Veracode API ID | No |
| `VERACODE_API_KEY` | Veracode API key | No |
| `ACUNETIX_URL` | Acunetix server URL | No |
| `ACUNETIX_API_KEY` | Acunetix API key | No |

### Security Tool Configuration

Each security tool requires specific configuration files:

- **acunetix-config.json** - Acunetix scan configuration
- **veracode.json** - Veracode application profiles
- **sonarqube-project.properties** - SonarQube project settings

## Architecture

### Application Structure
```
├── app.py              # Flask application factory
├── main.py             # Application entry point
├── routes.py           # Web routes and API endpoints
├── models.py           # SQLAlchemy database models
├── security_scanner.py # Security scanning orchestration
├── config.py           # Configuration management
├── templates/          # Jinja2 templates
│   ├── base.html
│   ├── dashboard.html
│   ├── scans.html
│   └── vulnerabilities.html
├── static/             # Static assets
│   ├── css/
│   └── js/
├── .github/workflows/  # CI/CD pipeline
└── terraform/          # Infrastructure as Code
```

### Database Schema

#### SecurityScan Model
- `id` - Primary key
- `scan_type` - Type of scan (SAST, DAST, IaC)
- `target` - Scan target (project, URL, etc.)
- `status` - Scan status (pending, running, completed, failed)
- `progress` - Scan progress percentage
- `created_at` - Scan creation timestamp
- `completed_at` - Scan completion timestamp

#### Vulnerability Model
- `id` - Primary key
- `scan_id` - Foreign key to SecurityScan
- `severity` - Vulnerability severity (Critical, High, Medium, Low)
- `vulnerability_type` - Type of vulnerability
- `description` - Vulnerability description
- `file_path` - Affected file path
- `line_number` - Line number where vulnerability exists
- `cwe_id` - Common Weakness Enumeration ID
- `cvss_score` - Common Vulnerability Scoring System score
- `remediation` - Remediation guidance
- `discovered_at` - Discovery timestamp

#### ScanMetrics Model
- `id` - Primary key
- `scan_date` - Date of metrics collection
- `total_scans` - Total number of scans
- `successful_scans` - Number of successful scans
- `failed_scans` - Number of failed scans
- `total_vulnerabilities` - Total vulnerabilities found
- `high_vulnerabilities` - High severity vulnerabilities
- `critical_vulnerabilities` - Critical severity vulnerabilities

## API Documentation

### REST Endpoints

#### Start New Scan
```http
POST /api/scan/start
Content-Type: application/json

{
  "scan_type": "SAST|DAST|IaC",
  "target": "target_identifier"
}
```

#### Get Scan Status
```http
GET /api/scan/{scan_id}/status
```

#### Get Vulnerabilities
```http
GET /api/vulnerabilities
```

#### Real-time Events
```http
GET /api/events
Accept: text/event-stream
```

### WebSocket Events

The application uses Server-Sent Events for real-time updates:

- `scan_progress` - Scan progress updates
- `new_vulnerability` - New vulnerability discovery
- `scan_complete` - Scan completion notification

## CI/CD Pipeline

### GitHub Actions Workflow

The included GitHub Actions workflow (`security-pipeline.yml`) provides:

1. **Code Quality Checks**
   - SonarQube analysis
   - Code coverage reporting
   - Linting and formatting

2. **Security Scanning**
   - SAST with Checkmarx
   - Dependency vulnerability scanning
   - Container image scanning

3. **Testing**
   - Unit tests with pytest
   - Integration tests
   - End-to-end tests

4. **Deployment**
   - Automated deployment to staging
   - Production deployment on release tags

### Triggering Pipeline

```bash
# Push to trigger CI/CD
git push origin main

# Create release for production deployment
git tag -a v1.0.0 -m "Release version 1.0.0"
git push origin v1.0.0
```

## Infrastructure Deployment

### Terraform Configuration

The `terraform/` directory contains Infrastructure as Code for AWS deployment:

- **security.tf** - Main security infrastructure
- **variables.tf** - Configuration variables
- **outputs.tf** - Infrastructure outputs

### Deployment Steps

1. **Configure AWS credentials**
   ```bash
   aws configure
   ```

2. **Initialize Terraform**
   ```bash
   cd terraform
   terraform init
   ```

3. **Plan deployment**
   ```bash
   terraform plan
   ```

4. **Deploy infrastructure**
   ```bash
   terraform apply
   ```

### Infrastructure Components

- **VPC** - Virtual Private Cloud with security groups
- **ECS** - Elastic Container Service for application hosting
- **RDS** - Managed PostgreSQL database
- **ALB** - Application Load Balancer with SSL termination
- **CloudWatch** - Logging and monitoring
- **IAM** - Identity and Access Management roles

## Security Features

![policy management](https://github.com/Reaishma/Security-scanner/blob/main/Screenshot_20250904-111737_1.jpg)

### Authentication & Authorization
- Session-based authentication with Flask-Login
- CSRF protection with Flask-WTF
- Secure session configuration
- Role-based access control

### Data Protection
- Password hashing with Werkzeug
- SQL injection prevention with SQLAlchemy ORM
- XSS protection with template escaping
- Secure HTTP headers

### Infrastructure Security
- VPC isolation with private subnets
- Security groups with minimal required access
- SSL/TLS encryption in transit
- Encryption at rest for database
- Regular security scanning and updates

## Development

### Running in Development Mode

1. **Set debug environment**
   ```bash
   export FLASK_ENV=development
   export FLASK_DEBUG=1
   ```

2. **Run with auto-reload**
   ```bash
   python main.py
   ```

### Testing

```bash
# Run unit tests
pytest tests/

# Run with coverage
pytest --cov=app tests/

# Run specific test file
pytest tests/test_security_scanner.py
```

### Code Quality

```bash
# Format code
black app.py routes.py models.py

# Lint code
flake8 app.py routes.py models.py

# Type checking
mypy app.py routes.py models.py
```

## Monitoring and Alerting

### Application Metrics
- Scan execution time and success rates
- Vulnerability discovery trends
- System performance metrics
- Error rates and debugging information

### Log Management
- Structured logging with JSON format
- Centralized log aggregation
- Real-time log monitoring
- Alert rules for critical errors

### Health Checks
- Application health endpoint
- Database connectivity checks
- External service availability
- Automated recovery procedures

## Third-party Services
- **CDN Resources**: Bootstrap CSS, Chart.js, and Feather Icons served from CDN for performance
- **Database Support**: SQLAlchemy with multi-database compatibility (SQLite, PostgreSQL)
- **Background Services**: APScheduler for automated scanning and maintenance tasks
- **Security Standards**: OWASP Top 10, SANS Top 25, PCI DSS, GDPR, SOC2, and NIST compliance checking

## Troubleshooting

### Common Issues

1. **Database Connection Errors**
   ```bash
   # Check database URL
   echo $DATABASE_URL
   
   # Test connection
   psql $DATABASE_URL -c "SELECT 1;"
   ```

2. **Real-time Updates Not Working**
   - Check Server-Sent Events connection
   - Verify application context in event stream
   - Monitor browser console for JavaScript errors

3. **Scan Failures**
   - Verify tool configurations
   - Check API credentials and endpoints
   - Review scan logs for detailed error messages

### Debug Mode

Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Performance Optimization

- Enable database connection pooling
- Configure appropriate timeout values
- Use caching for frequently accessed data
- Optimize database queries

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Make your changes
4. Add tests for new functionality
5. Commit your changes (`git commit -am 'Add new feature'`)
6. Push to the branch (`git push origin feature/new-feature`)
7. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For questions, issues, or feature requests:

- Create an issue on GitHub

## Changelog

### Version 1.0.0
- Initial release with core security scanning features
- Real-time vulnerability monitoring
- CI/CD pipeline integration
- Infrastructure as Code deployment
- Comprehensive documentation and testing

---

*Security Scanner - Comprehensive security monitoring for modern applications*
