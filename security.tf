# AWS Provider Configuration
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  
  backend "s3" {
    bucket         = "security-scanner-terraform-state"
    key            = "infrastructure/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-locks"
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "Security Scanner Dashboard"
      Environment = var.environment
      Owner       = "Security Team"
      CostCenter  = "Security"
      Compliance  = "PCI-DSS,SOC2,GDPR"
    }
  }
}

# Variables
variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "application_name" {
  description = "Application name"
  type        = string
  default     = "security-scanner-dashboard"
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# KMS Key for encryption
resource "aws_kms_key" "application_key" {
  description             = "KMS key for Security Scanner Dashboard encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow application access"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.application_role.arn
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "${var.application_name}-kms-key"
  }
}

resource "aws_kms_alias" "application_key_alias" {
  name          = "alias/${var.application_name}-key"
  target_key_id = aws_kms_key.application_key.key_id
}

# Secrets Manager for sensitive configuration
resource "aws_secretsmanager_secret" "application_secrets" {
  name                    = "${var.application_name}-secrets"
  description             = "Sensitive configuration for Security Scanner Dashboard"
  kms_key_id              = aws_kms_key.application_key.arn
  recovery_window_in_days = 7

  tags = {
    Name = "${var.application_name}-secrets"
  }
}

resource "aws_secretsmanager_secret_version" "application_secrets" {
  secret_id = aws_secretsmanager_secret.application_secrets.id
  
  secret_string = jsonencode({
    SESSION_SECRET       = random_password.session_secret.result
    DATABASE_PASSWORD    = random_password.db_password.result
    VERACODE_API_KEY    = var.veracode_api_key
    CHECKMARX_PASSWORD  = var.checkmarx_password
    ACUNETIX_API_KEY    = var.acunetix_api_key
    SONAR_TOKEN         = var.sonar_token
  })
}

# Random passwords
resource "random_password" "session_secret" {
  length  = 32
  special = true
}

resource "random_password" "db_password" {
  length  = 16
  special = true
}

# VPC Configuration
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.application_name}-vpc"
  }
}

# Private subnets for application
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 1}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "${var.application_name}-private-subnet-${count.index + 1}"
    Type = "Private"
  }
}

# Public subnets for load balancer
resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.${count.index + 10}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.application_name}-public-subnet-${count.index + 1}"
    Type = "Public"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.application_name}-igw"
  }
}

# NAT Gateway for private subnet outbound access
resource "aws_eip" "nat" {
  count  = 2
  domain = "vpc"

  tags = {
    Name = "${var.application_name}-nat-eip-${count.index + 1}"
  }
}

resource "aws_nat_gateway" "main" {
  count         = 2
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = {
    Name = "${var.application_name}-nat-${count.index + 1}"
  }

  depends_on = [aws_internet_gateway.main]
}

# Route tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${var.application_name}-public-rt"
  }
}

resource "aws_route_table" "private" {
  count  = 2
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[count.index].id
  }

  tags = {
    Name = "${var.application_name}-private-rt-${count.index + 1}"
  }
}

# Route table associations
resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# Security Groups
resource "aws_security_group" "alb" {
  name        = "${var.application_name}-alb-sg"
  description = "Security group for Application Load Balancer"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS access"
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP access (redirect to HTTPS)"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = {
    Name = "${var.application_name}-alb-sg"
  }
}

resource "aws_security_group" "application" {
  name        = "${var.application_name}-app-sg"
  description = "Security group for application instances"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 5000
    to_port         = 5000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
    description     = "Application port from ALB"
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS outbound"
  }

  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP outbound"
  }

  egress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.database.id]
    description     = "Database access"
  }

  tags = {
    Name = "${var.application_name}-app-sg"
  }
}

resource "aws_security_group" "database" {
  name        = "${var.application_name}-db-sg"
  description = "Security group for database"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.application.id]
    description     = "Database access from application"
  }

  tags = {
    Name = "${var.application_name}-db-sg"
  }
}

# Database subnet group
resource "aws_db_subnet_group" "main" {
  name       = "${var.application_name}-db-subnet-group"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name = "${var.application_name}-db-subnet-group"
  }
}

# RDS Database
resource "aws_db_instance" "main" {
  identifier = "${var.application_name}-db"

  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.micro"

  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.application_key.arn

  db_name  = "securityscanner"
  username = "appuser"
  password = random_password.db_password.result

  vpc_security_group_ids = [aws_security_group.database.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name

  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"

  skip_final_snapshot = false
  final_snapshot_identifier = "${var.application_name}-db-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"

  enabled_cloudwatch_logs_exports = ["postgresql"]
  monitoring_interval             = 60
  monitoring_role_arn            = aws_iam_role.rds_monitoring.arn

  performance_insights_enabled = true
  performance_insights_kms_key_id = aws_kms_key.application_key.arn

  deletion_protection = true

  tags = {
    Name = "${var.application_name}-database"
  }
}

# IAM Role for application
resource "aws_iam_role" "application_role" {
  name = "${var.application_name}-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.application_name}-app-role"
  }
}

# IAM Policy for application
resource "aws_iam_role_policy" "application_policy" {
  name = "${var.application_name}-app-policy"
  role = aws_iam_role.application_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = aws_secretsmanager_secret.application_secrets.arn
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.application_key.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/ec2/${var.application_name}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "SecurityScanner"
          }
        }
      }
    ]
  })
}

# IAM instance profile
resource "aws_iam_instance_profile" "application_profile" {
  name = "${var.application_name}-app-profile"
  role = aws_iam_role.application_role.name
}

# IAM Role for RDS monitoring
resource "aws_iam_role" "rds_monitoring" {
  name = "${var.application_name}-rds-monitoring"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "application" {
  name              = "/aws/ec2/${var.application_name}"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.application_key.arn

  tags = {
    Name = "${var.application_name}-log-group"
  }
}

# S3 Bucket for application data and backups
resource "aws_s3_bucket" "application_data" {
  bucket = "${var.application_name}-data-${random_string.bucket_suffix.result}"

  tags = {
    Name = "${var.application_name}-data-bucket"
  }
}

resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

resource "aws_s3_bucket_versioning" "application_data" {
  bucket = aws_s3_bucket.application_data.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "application_data" {
  bucket = aws_s3_bucket.application_data.id

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.application_key.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "application_data" {
  bucket = aws_s3_bucket.application_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "application_data" {
  bucket = aws_s3_bucket.application_data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyInsecureConnections"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.application_data.arn,
          "${aws_s3_bucket.application_data.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# ACM Certificate for HTTPS
resource "aws_acm_certificate" "main" {
  domain_name       = var.domain_name
  validation_method = "DNS"

  subject_alternative_names = [
    "*.${var.domain_name}"
  ]

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${var.application_name}-certificate"
  }
}

variable "domain_name" {
  description = "Domain name for the application"
  type        = string
  default     = "security-scanner.company.com"
}

# Application Load Balancer
resource "aws_lb" "main" {
  name               = "${var.application_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  enable_deletion_protection = true
  enable_http2              = true
  drop_invalid_header_fields = true

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.bucket
    prefix  = "alb-logs"
    enabled = true
  }

  tags = {
    Name = "${var.application_name}-alb"
  }
}

# S3 bucket for ALB access logs
resource "aws_s3_bucket" "alb_logs" {
  bucket = "${var.application_name}-alb-logs-${random_string.bucket_suffix.result}"

  tags = {
    Name = "${var.application_name}-alb-logs"
  }
}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_elb_service_account.main.id}:root"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs.arn}/alb-logs/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
      },
      {
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs.arn}/alb-logs/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.alb_logs.arn
      }
    ]
  })
}

data "aws_elb_service_account" "main" {}

# WAF for application protection
resource "aws_wafv2_web_acl" "main" {
  name  = "${var.application_name}-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.application_name}-CommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.application_name}-KnownBadInputs"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "RateLimitRule"
    priority = 3

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.application_name}-RateLimit"
      sampled_requests_enabled   = true
    }
  }

  tags = {
    Name = "${var.application_name}-waf"
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.application_name}-WAF"
    sampled_requests_enabled   = true
  }
}

# Variables for sensitive data
variable "veracode_api_key" {
  description = "Veracode API key"
  type        = string
  sensitive   = true
  default     = ""
}

variable "checkmarx_password" {
  description = "Checkmarx password"
  type        = string
  sensitive   = true
  default     = ""
}

variable "acunetix_api_key" {
  description = "Acunetix API key"
  type        = string
  sensitive   = true
  default     = ""
}

variable "sonar_token" {
  description = "SonarQube token"
  type        = string
  sensitive   = true
  default     = ""
}

# Outputs
output "database_endpoint" {
  description = "RDS instance endpoint"
  value       = aws_db_instance.main.endpoint
  sensitive   = true
}

output "kms_key_id" {
  description = "KMS key ID for encryption"
  value       = aws_kms_key.application_key.key_id
}

output "secrets_manager_arn" {
  description = "Secrets Manager secret ARN"
  value       = aws_secretsmanager_secret.application_secrets.arn
}

output "load_balancer_dns" {
  description = "Load balancer DNS name"
  value       = aws_lb.main.dns_name
}

output "s3_bucket_name" {
  description = "S3 bucket name for application data"
  value       = aws_s3_bucket.application_data.id
}

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "private_subnet_ids" {
  description = "Private subnet IDs"
  value       = aws_subnet.private[*].id
}

output "application_role_arn" {
  description = "Application IAM role ARN"
  value       = aws_iam_role.application_role.arn
}
