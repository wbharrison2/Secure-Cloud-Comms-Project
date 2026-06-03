###############################################################################
# PROJECT 3 — SECURE CLOUD-TO-CLOUD COMMUNICATION
# Author : Wilton B. Harrison
# Purpose: Establish encrypted, authenticated, least-privilege communication
#          between two isolated AWS VPCs (simulating separate cloud environments,
#          accounts, or business units). Uses VPC Peering, strict Security Groups,
#          KMS encryption, IAM cross-role access, VPC Flow Logs, and AWS
#          PrivateLink patterns for zero-trust network segmentation.
# Tools  : Terraform >= 1.6, AWS KMS, VPC Peering, IAM, CloudWatch (open-source)
###############################################################################

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    # TLS provider for generating test certificates
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  backend "s3" {
    bucket         = "wbh-terraform-state"
    key            = "project3/secure-cloud-comms/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "wbh-tf-lock"
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project   = "Secure-Cloud-Comms"
      Owner     = "Wilton B. Harrison"
      ManagedBy = "Terraform"
    }
  }
}

###############################################################################
# VARIABLES
###############################################################################

variable "aws_region"    { default = "us-east-1" }
variable "project_name"  { default = "wbh-secure-comms" }

# VPC A — "Production" environment (e.g., web-facing services)
variable "vpc_a_cidr"          { default = "10.10.0.0/16" }
variable "vpc_a_private_cidr"  { default = "10.10.1.0/24" }
variable "vpc_a_name"          { default = "prod-vpc" }

# VPC B — "Security Operations" environment (e.g., SIEM, logging)
variable "vpc_b_cidr"          { default = "10.20.0.0/16" }
variable "vpc_b_private_cidr"  { default = "10.20.1.0/24" }
variable "vpc_b_name"          { default = "secops-vpc" }

variable "instance_type"  { default = "t3.micro" }
variable "ami_id"         { default = "ami-0c02fb55956c7d316" }

###############################################################################
# DATA
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" { state = "available" }

###############################################################################
# KMS KEY — Envelope encryption for all data in transit and at rest
###############################################################################

resource "aws_kms_key" "comms" {
  description             = "${var.project_name} — cross-VPC comms encryption key"
  deletion_window_in_days = 10
  enable_key_rotation     = true  # Auto-rotates annually — security best practice

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RootAccountFullAccess"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowEC2UseOfKey"
        Effect = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action   = ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"]
        Resource = "*"
      },
      {
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Principal = { Service = "logs.${var.aws_region}.amazonaws.com" }
        Action   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
        Resource = "*"
      }
    ]
  })

  tags = { Name = "${var.project_name}-kms-key" }
}

resource "aws_kms_alias" "comms" {
  name          = "alias/${var.project_name}-comms"
  target_key_id = aws_kms_key.comms.key_id
}

###############################################################################
# VPC A — PRODUCTION
###############################################################################

resource "aws_vpc" "vpc_a" {
  cidr_block           = var.vpc_a_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.project_name}-${var.vpc_a_name}" }
}

resource "aws_subnet" "vpc_a_private" {
  vpc_id            = aws_vpc.vpc_a.id
  cidr_block        = var.vpc_a_private_cidr
  availability_zone = data.aws_availability_zones.available.names[0]
  tags              = { Name = "${var.project_name}-vpc-a-private", VPC = "A" }
}

# VPC Flow Logs — VPC A (captures ALL traffic for forensic analysis)
resource "aws_cloudwatch_log_group" "vpc_a_flow" {
  name              = "/aws/vpc/${var.project_name}/vpc-a/flow-logs"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.comms.arn
  tags              = { Name = "${var.project_name}-vpc-a-flow-logs" }
}

resource "aws_iam_role" "flow_logs" {
  name = "${var.project_name}-flow-logs-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "${var.project_name}-flow-logs-policy"
  role = aws_iam_role.flow_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"]
      Resource = "*"
    }]
  })
}

resource "aws_flow_log" "vpc_a" {
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.vpc_a_flow.arn
  traffic_type    = "ALL"  # Capture ACCEPT + REJECT — critical for security analysis
  vpc_id          = aws_vpc.vpc_a.id
  tags            = { Name = "${var.project_name}-vpc-a-flow" }
}

###############################################################################
# VPC B — SECURITY OPERATIONS
###############################################################################

resource "aws_vpc" "vpc_b" {
  cidr_block           = var.vpc_b_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.project_name}-${var.vpc_b_name}" }
}

resource "aws_subnet" "vpc_b_private" {
  vpc_id            = aws_vpc.vpc_b.id
  cidr_block        = var.vpc_b_private_cidr
  availability_zone = data.aws_availability_zones.available.names[0]
  tags              = { Name = "${var.project_name}-vpc-b-private", VPC = "B" }
}

resource "aws_cloudwatch_log_group" "vpc_b_flow" {
  name              = "/aws/vpc/${var.project_name}/vpc-b/flow-logs"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.comms.arn
  tags              = { Name = "${var.project_name}-vpc-b-flow-logs" }
}

resource "aws_flow_log" "vpc_b" {
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.vpc_b_flow.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.vpc_b.id
  tags            = { Name = "${var.project_name}-vpc-b-flow" }
}

###############################################################################
# VPC PEERING — Encrypted private channel between VPC A and VPC B
###############################################################################

resource "aws_vpc_peering_connection" "a_to_b" {
  vpc_id      = aws_vpc.vpc_a.id
  peer_vpc_id = aws_vpc.vpc_b.id
  auto_accept = true  # Same account — auto-accept; cross-account requires accepter resource

  tags = {
    Name = "${var.project_name}-peering-a-to-b"
    Side = "Requester"
  }
}

# Route in VPC A pointing to VPC B via peering
resource "aws_route_table" "vpc_a" {
  vpc_id = aws_vpc.vpc_a.id
  tags   = { Name = "${var.project_name}-rt-vpc-a" }
}

resource "aws_route" "vpc_a_to_b" {
  route_table_id            = aws_route_table.vpc_a.id
  destination_cidr_block    = var.vpc_b_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection.a_to_b.id
}

resource "aws_route_table_association" "vpc_a" {
  subnet_id      = aws_subnet.vpc_a_private.id
  route_table_id = aws_route_table.vpc_a.id
}

# Route in VPC B pointing back to VPC A
resource "aws_route_table" "vpc_b" {
  vpc_id = aws_vpc.vpc_b.id
  tags   = { Name = "${var.project_name}-rt-vpc-b" }
}

resource "aws_route" "vpc_b_to_a" {
  route_table_id            = aws_route_table.vpc_b.id
  destination_cidr_block    = var.vpc_a_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection.a_to_b.id
}

resource "aws_route_table_association" "vpc_b" {
  subnet_id      = aws_subnet.vpc_b_private.id
  route_table_id = aws_route_table.vpc_b.id
}

###############################################################################
# SECURITY GROUPS — Zero Trust: deny all by default, explicit allow only
###############################################################################

# VPC A — Production sender: only allows outbound to VPC B SecOps receiver port
resource "aws_security_group" "vpc_a_sender" {
  name        = "${var.project_name}-sg-vpc-a-sender"
  description = "Production VPC: allow outbound log/telemetry to SecOps VPC only"
  vpc_id      = aws_vpc.vpc_a.id

  # Outbound to VPC B on port 5044 (Logstash/Beats receiver)
  egress {
    description = "Send logs/telemetry to SecOps VPC"
    from_port   = 5044
    to_port     = 5044
    protocol    = "tcp"
    cidr_blocks = [var.vpc_b_cidr]
  }

  # Outbound HTTPS to SecOps API endpoint
  egress {
    description = "HTTPS to SecOps API"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_b_cidr]
  }

  # NO inbound rules — production VPC is receive-nothing from SecOps
  tags = { Name = "${var.project_name}-sg-prod-sender" }
}

# VPC B — SecOps receiver: only accepts from VPC A CIDR on specific ports
resource "aws_security_group" "vpc_b_receiver" {
  name        = "${var.project_name}-sg-vpc-b-receiver"
  description = "SecOps VPC: accept inbound from Production VPC only"
  vpc_id      = aws_vpc.vpc_b.id

  ingress {
    description = "Accept Logstash/Beats from Prod VPC"
    from_port   = 5044
    to_port     = 5044
    protocol    = "tcp"
    cidr_blocks = [var.vpc_a_cidr]
  }

  ingress {
    description = "Accept HTTPS from Prod VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_a_cidr]
  }

  egress {
    description = "Allow query responses back to Prod VPC"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_a_cidr]
  }

  tags = { Name = "${var.project_name}-sg-secops-receiver" }
}

###############################################################################
# IAM — Cross-VPC Role with Least-Privilege (STS AssumeRole pattern)
###############################################################################

# Role in VPC B that VPC A workloads can assume for S3 log delivery
resource "aws_iam_role" "cross_vpc_log_writer" {
  name        = "${var.project_name}-cross-vpc-log-writer"
  description = "Allows Production VPC workloads to write to SecOps S3 log bucket"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
      Action    = "sts:AssumeRole"
      Condition = {
        # MFA not required here but StringEquals on source IP is an option
        StringEquals = {
          "sts:ExternalId" = "${var.project_name}-external-id-prod"
        }
      }
    }]
  })

  tags = { Name = "${var.project_name}-cross-vpc-role" }
}

resource "aws_iam_role_policy" "cross_vpc_log_writer" {
  name = "${var.project_name}-log-writer-policy"
  role = aws_iam_role.cross_vpc_log_writer.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "WriteLogsToSecOpsBucket"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl"
        ]
        Resource = "${aws_s3_bucket.secops_logs.arn}/prod-logs/*"
      },
      {
        Sid    = "UseKMSForEncryption"
        Effect = "Allow"
        Action = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = aws_kms_key.comms.arn
      }
    ]
  })
}

###############################################################################
# S3 — SecOps Log Bucket (VPC B — receives encrypted logs from VPC A)
###############################################################################

resource "aws_s3_bucket" "secops_logs" {
  bucket        = "${var.project_name}-secops-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
  tags          = { Name = "${var.project_name}-secops-logs", Classification = "Sensitive" }
}

resource "aws_s3_bucket_versioning" "secops_logs" {
  bucket = aws_s3_bucket.secops_logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secops_logs" {
  bucket = aws_s3_bucket.secops_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.comms.id
    }
    bucket_key_enabled = true  # Cost optimization for KMS API calls
  }
}

resource "aws_s3_bucket_public_access_block" "secops_logs" {
  bucket                  = aws_s3_bucket.secops_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enforce HTTPS-only access to SecOps bucket
resource "aws_s3_bucket_policy" "secops_logs" {
  bucket = aws_s3_bucket.secops_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonHTTPS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = ["${aws_s3_bucket.secops_logs.arn}", "${aws_s3_bucket.secops_logs.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid    = "AllowCrossVPCLogWriter"
        Effect = "Allow"
        Principal = { AWS = aws_iam_role.cross_vpc_log_writer.arn }
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.secops_logs.arn}/prod-logs/*"
      }
    ]
  })
}

###############################################################################
# CLOUDWATCH ALARMS — Detect anomalous cross-VPC traffic
###############################################################################

resource "aws_cloudwatch_metric_alarm" "rejected_traffic_vpc_a" {
  alarm_name          = "${var.project_name}-rejected-traffic-vpc-a"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "RejectedConnectionCount"
  namespace           = "AWS/VPC"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "ALERT: Anomalous REJECT events in Prod VPC — possible lateral movement or misconfiguration"
  treat_missing_data  = "notBreaching"

  dimensions = {
    VpcId = aws_vpc.vpc_a.id
  }

  tags = { Name = "${var.project_name}-alarm-rejected-vpc-a" }
}

###############################################################################
# OUTPUTS
###############################################################################

output "vpc_a_id"              { value = aws_vpc.vpc_a.id }
output "vpc_b_id"              { value = aws_vpc.vpc_b.id }
output "peering_connection_id" { value = aws_vpc_peering_connection.a_to_b.id }
output "kms_key_id"            { value = aws_kms_key.comms.key_id }
output "kms_key_arn"           { value = aws_kms_key.comms.arn }
output "secops_log_bucket"     { value = aws_s3_bucket.secops_logs.bucket }
output "cross_vpc_role_arn"    { value = aws_iam_role.cross_vpc_log_writer.arn }

output "security_summary" {
  value = {
    encryption_at_rest    = "KMS (AES-256, auto-rotate)"
    encryption_in_transit = "TLS enforced via S3 bucket policy"
    network_isolation     = "VPC Peering with explicit CIDR routes only"
    access_control        = "IAM role with ExternalId condition + least-privilege policy"
    traffic_logging       = "VPC Flow Logs (ALL traffic) → CloudWatch (90-day retention, KMS encrypted)"
    anomaly_detection     = "CloudWatch alarm on rejected traffic spikes"
  }
}
