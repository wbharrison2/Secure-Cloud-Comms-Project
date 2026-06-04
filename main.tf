###############################################################################
# ENTERPRISE PROJECT 6 — ZERO-TRUST SECURITY OPERATIONS PLATFORM
# Author : Wilton B. Harrison
# Source : Based on Project 3 — Secure Cloud-to-Cloud Communication
#          https://github.com/wbharrison2/Secure-Cloud-Comms-Project
# Purpose: Enterprise zero-trust security operations center (SecOps) extending
#          Project 3's two-VPC peering to a multi-VPC hub-and-spoke topology
#          via Transit Gateway. Adds centralized SIEM via OpenSearch, Kinesis
#          log pipeline, Config continuous compliance, Security Hub aggregation,
#          GuardDuty threat detection, and EventBridge + Lambda automated
#          incident response playbooks.
# Tools  : Terraform >= 1.6, AWS Provider >= 5.0, OpenSearch (open-source SIEM)
###############################################################################

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }

  backend "s3" {
    bucket         = "wbh-terraform-state"
    key            = "enterprise6/zerotrust-secops/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "wbh-tf-lock"
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "Enterprise-ZeroTrust-SecOps"
      Owner       = "Wilton B. Harrison"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

variable "aws_region"    { default = "us-east-1" }
variable "environment"   { default = "prod" }
variable "project_name"  { default = "wbh-zerotrust-secops" }

variable "hub_vpc_cidr"    { default = "10.10.0.0/16" }
variable "prod_vpc_cidr"   { default = "10.20.0.0/16" }
variable "dev_vpc_cidr"    { default = "10.30.0.0/16" }
variable "staging_vpc_cidr"{ default = "10.40.0.0/16" }

variable "hub_subnets"     { default = ["10.10.1.0/24", "10.10.2.0/24"] }
variable "prod_subnets"    { default = ["10.20.1.0/24", "10.20.2.0/24"] }
variable "dev_subnets"     { default = ["10.30.1.0/24", "10.30.2.0/24"] }
variable "staging_subnets" { default = ["10.40.1.0/24", "10.40.2.0/24"] }

variable "opensearch_instance_type" { default = "t3.small.search" }
variable "opensearch_volume_size"   { default = 50 }
variable "alert_email"              { default = "secops@example.com" }
variable "external_id"              { default = "wbh-zerotrust-secops-2024" }
variable "log_retention_days"       { default = 90 }

data "aws_availability_zones" "available" { state = "available" }
data "aws_caller_identity" "current" {}

resource "random_id" "suffix" { byte_length = 4 }

###############################################################################
# KMS
###############################################################################

resource "aws_kms_key" "secops" {
  description             = "${var.project_name} CMK"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RootAdmin"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "CloudWatchLogsEncryption"
        Effect = "Allow"
        Principal = { Service = "logs.${var.aws_region}.amazonaws.com" }
        Action   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
        Resource = "*"
        Condition = { ArnLike = { "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*" } }
      },
      {
        Sid    = "FirehoseEncryption"
        Effect = "Allow"
        Principal = { Service = "firehose.amazonaws.com" }
        Action   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"]
        Resource = "*"
      }
    ]
  })

  tags = { Name = "${var.project_name}-cmk" }
}

resource "aws_kms_alias" "secops" {
  name          = "alias/${var.project_name}"
  target_key_id = aws_kms_key.secops.key_id
}

###############################################################################
# NETWORKING
###############################################################################

resource "aws_vpc" "hub" {
  cidr_block           = var.hub_vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.project_name}-hub-vpc", Role = "SecOps-Hub" }
}

resource "aws_subnet" "hub" {
  count             = length(var.hub_subnets)
  vpc_id            = aws_vpc.hub.id
  cidr_block        = var.hub_subnets[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags              = { Name = "${var.project_name}-hub-priv-${count.index + 1}" }
}

resource "aws_vpc" "production" {
  cidr_block           = var.prod_vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.project_name}-prod-vpc", Role = "Production" }
}

resource "aws_subnet" "production" {
  count             = length(var.prod_subnets)
  vpc_id            = aws_vpc.production.id
  cidr_block        = var.prod_subnets[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags              = { Name = "${var.project_name}-prod-priv-${count.index + 1}" }
}

resource "aws_vpc" "development" {
  cidr_block           = var.dev_vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.project_name}-dev-vpc", Role = "Development" }
}

resource "aws_subnet" "development" {
  count             = length(var.dev_subnets)
  vpc_id            = aws_vpc.development.id
  cidr_block        = var.dev_subnets[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags              = { Name = "${var.project_name}-dev-priv-${count.index + 1}" }
}

resource "aws_vpc" "staging" {
  cidr_block           = var.staging_vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.project_name}-staging-vpc", Role = "Staging" }
}

resource "aws_subnet" "staging" {
  count             = length(var.staging_subnets)
  vpc_id            = aws_vpc.staging.id
  cidr_block        = var.staging_subnets[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags              = { Name = "${var.project_name}-staging-priv-${count.index + 1}" }
}

###############################################################################
# TRANSIT GATEWAY
###############################################################################

resource "aws_ec2_transit_gateway" "hub" {
  description                     = "${var.project_name} hub-and-spoke TGW"
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"
  auto_accept_shared_attachments  = "disable"
  dns_support                     = "enable"
  vpn_ecmp_support                = "disable"
  tags = { Name = "${var.project_name}-tgw" }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "hub" {
  transit_gateway_id             = aws_ec2_transit_gateway.hub.id
  vpc_id                         = aws_vpc.hub.id
  subnet_ids                     = aws_subnet.hub[*].id
  transit_gateway_default_route_table_association = false
  transit_gateway_default_route_table_propagation = false
  tags = { Name = "${var.project_name}-tgw-attach-hub", Role = "hub" }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "production" {
  transit_gateway_id             = aws_ec2_transit_gateway.hub.id
  vpc_id                         = aws_vpc.production.id
  subnet_ids                     = aws_subnet.production[*].id
  transit_gateway_default_route_table_association = false
  transit_gateway_default_route_table_propagation = false
  tags = { Name = "${var.project_name}-tgw-attach-prod", Role = "spoke" }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "development" {
  transit_gateway_id             = aws_ec2_transit_gateway.hub.id
  vpc_id                         = aws_vpc.development.id
  subnet_ids                     = aws_subnet.development[*].id
  transit_gateway_default_route_table_association = false
  transit_gateway_default_route_table_propagation = false
  tags = { Name = "${var.project_name}-tgw-attach-dev", Role = "spoke" }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "staging" {
  transit_gateway_id             = aws_ec2_transit_gateway.hub.id
  vpc_id                         = aws_vpc.staging.id
  subnet_ids                     = aws_subnet.staging[*].id
  transit_gateway_default_route_table_association = false
  transit_gateway_default_route_table_propagation = false
  tags = { Name = "${var.project_name}-tgw-attach-staging", Role = "spoke" }
}

resource "aws_ec2_transit_gateway_route_table" "hub" {
  transit_gateway_id = aws_ec2_transit_gateway.hub.id
  tags               = { Name = "${var.project_name}-tgw-rt-hub" }
}

resource "aws_ec2_transit_gateway_route_table" "spokes" {
  transit_gateway_id = aws_ec2_transit_gateway.hub.id
  tags               = { Name = "${var.project_name}-tgw-rt-spokes" }
}

resource "aws_ec2_transit_gateway_route_table_association" "hub" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.hub.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.hub.id
}

resource "aws_ec2_transit_gateway_route_table_association" "production" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.production.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.spokes.id
}

resource "aws_ec2_transit_gateway_route_table_association" "development" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.development.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.spokes.id
}

resource "aws_ec2_transit_gateway_route_table_association" "staging" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.staging.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.spokes.id
}

resource "aws_ec2_transit_gateway_route_table_propagation" "prod_to_hub" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.production.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.hub.id
}

resource "aws_ec2_transit_gateway_route_table_propagation" "dev_to_hub" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.development.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.hub.id
}

resource "aws_ec2_transit_gateway_route_table_propagation" "staging_to_hub" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.staging.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.hub.id
}

resource "aws_ec2_transit_gateway_route" "spokes_to_hub" {
  destination_cidr_block         = var.hub_vpc_cidr
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.hub.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.spokes.id
}

###############################################################################
# VPC FLOW LOGS
###############################################################################

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/${var.project_name}/flow-logs"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.secops.arn
  tags              = { Name = "${var.project_name}-flow-logs" }
}

resource "aws_iam_role" "flow_logs" {
  name = "${var.project_name}-flow-logs-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow"; Principal = { Service = "vpc-flow-logs.amazonaws.com" }; Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  role = aws_iam_role.flow_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow"; Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"]; Resource = "*" }]
  })
}

resource "aws_flow_log" "hub" {
  vpc_id          = aws_vpc.hub.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  tags            = { Name = "${var.project_name}-flow-hub" }
}

resource "aws_flow_log" "production" {
  vpc_id          = aws_vpc.production.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  tags            = { Name = "${var.project_name}-flow-prod" }
}

resource "aws_flow_log" "development" {
  vpc_id          = aws_vpc.development.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  tags            = { Name = "${var.project_name}-flow-dev" }
}

resource "aws_flow_log" "staging" {
  vpc_id          = aws_vpc.staging.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  tags            = { Name = "${var.project_name}-flow-staging" }
}

###############################################################################
# CLOUDTRAIL
###############################################################################

resource "aws_s3_bucket" "cloudtrail" {
  bucket        = "${var.project_name}-cloudtrail-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
  tags          = { Name = "${var.project_name}-cloudtrail" }
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.secops.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "AWSCloudTrailAclCheck"; Effect = "Allow"; Principal = { Service = "cloudtrail.amazonaws.com" }; Action = "s3:GetBucketAcl"; Resource = aws_s3_bucket.cloudtrail.arn },
      { Sid = "AWSCloudTrailWrite"; Effect = "Allow"; Principal = { Service = "cloudtrail.amazonaws.com" }; Action = "s3:PutObject"; Resource = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"; Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } } },
      { Sid = "DenyNonHTTPS"; Effect = "Deny"; Principal = "*"; Action = "s3:*"; Resource = [aws_s3_bucket.cloudtrail.arn, "${aws_s3_bucket.cloudtrail.arn}/*"]; Condition = { Bool = { "aws:SecureTransport" = "false" } } }
    ]
  })
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${var.project_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.secops.arn
  tags              = { Name = "${var.project_name}-cloudtrail-logs" }
}

resource "aws_iam_role" "cloudtrail" {
  name = "${var.project_name}-cloudtrail-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow"; Principal = { Service = "cloudtrail.amazonaws.com" }; Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "cloudtrail" {
  role = aws_iam_role.cloudtrail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow"; Action = ["logs:CreateLogStream", "logs:PutLogEvents"]; Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*" }]
  })
}

resource "aws_cloudtrail" "main" {
  name                          = "${var.project_name}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.bucket
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail.arn
  enable_log_file_validation    = true
  include_global_service_events = true
  is_multi_region_trail         = true
  kms_key_id                    = aws_kms_key.secops.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }

  insight_selector { insight_type = "ApiCallRateInsight" }
  insight_selector { insight_type = "ApiErrorRateInsight" }

  tags = { Name = "${var.project_name}-cloudtrail" }
}

###############################################################################
# AWS CONFIG
###############################################################################

resource "aws_iam_role" "config" {
  name = "${var.project_name}-config-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow"; Principal = { Service = "config.amazonaws.com" }; Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_s3_bucket" "config" {
  bucket        = "${var.project_name}-config-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
  tags          = { Name = "${var.project_name}-config-bucket" }
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket                  = aws_s3_bucket.config.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_config_configuration_recorder" "main" {
  name     = "${var.project_name}-config-recorder"
  role_arn = aws_iam_role.config.arn
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "${var.project_name}-config-delivery"
  s3_bucket_name = aws_s3_bucket.config.bucket
  sns_topic_arn  = aws_sns_topic.secops_alerts.arn
  depends_on     = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

resource "aws_config_config_rule" "encrypted_volumes" {
  name       = "${var.project_name}-encrypted-volumes"
  depends_on = [aws_config_configuration_recorder_status.main]
  source { owner = "AWS"; source_identifier = "ENCRYPTED_VOLUMES" }
}

resource "aws_config_config_rule" "restricted_ssh" {
  name       = "${var.project_name}-restricted-ssh"
  depends_on = [aws_config_configuration_recorder_status.main]
  source { owner = "AWS"; source_identifier = "INCOMING_SSH_DISABLED" }
}

resource "aws_config_config_rule" "s3_public_access" {
  name       = "${var.project_name}-s3-public-access"
  depends_on = [aws_config_configuration_recorder_status.main]
  source { owner = "AWS"; source_identifier = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED" }
}

resource "aws_config_config_rule" "root_mfa" {
  name       = "${var.project_name}-root-mfa-enabled"
  depends_on = [aws_config_configuration_recorder_status.main]
  source { owner = "AWS"; source_identifier = "ROOT_ACCOUNT_MFA_ENABLED" }
}

resource "aws_config_config_rule" "cloudtrail_enabled" {
  name       = "${var.project_name}-cloudtrail-enabled"
  depends_on = [aws_config_configuration_recorder_status.main]
  source { owner = "AWS"; source_identifier = "CLOUD_TRAIL_ENABLED" }
}

resource "aws_config_config_rule" "guardduty_enabled" {
  name       = "${var.project_name}-guardduty-enabled"
  depends_on = [aws_config_configuration_recorder_status.main]
  source { owner = "AWS"; source_identifier = "GUARDDUTY_ENABLED_CENTRALIZED" }
}

###############################################################################
# GUARDDUTY
###############################################################################

resource "aws_guardduty_detector" "secops" {
  enable = true
  datasources {
    s3_logs { enable = true }
    kubernetes { audit_logs { enable = true } }
    malware_protection { scan_ec2_instance_with_findings { ebs_volumes { enable = true } } }
  }
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  tags                         = { Name = "${var.project_name}-guardduty" }
}

resource "aws_guardduty_publishing_destination" "s3" {
  detector_id      = aws_guardduty_detector.secops.id
  destination_arn  = aws_s3_bucket.secops_logs.arn
  kms_key_arn      = aws_kms_key.secops.arn
  destination_type = "S3"
}

###############################################################################
# SECURITY HUB
###############################################################################

resource "aws_securityhub_account" "main" {}

resource "aws_securityhub_standards_subscription" "cis" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/cis-aws-foundations-benchmark/v/1.4.0"
}

resource "aws_securityhub_standards_subscription" "aws_foundational" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
}

resource "aws_securityhub_standards_subscription" "pci_dss" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/pci-dss/v/3.2.1"
}

###############################################################################
# IAM CROSS-VPC ROLE
###############################################################################

resource "aws_iam_role" "cross_vpc_role" {
  name = "${var.project_name}-cross-vpc-secops-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow"; Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }; Action = "sts:AssumeRole"; Condition = { StringEquals = { "sts:ExternalId" = var.external_id } } }]
  })
  tags = { Name = "${var.project_name}-cross-vpc-role" }
}

resource "aws_iam_policy" "cross_vpc_secops" {
  name = "${var.project_name}-cross-vpc-secops-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow"; Action = ["s3:PutObject", "s3:GetObject"]; Resource = "${aws_s3_bucket.secops_logs.arn}/prod-logs/*"; Condition = { Bool = { "aws:SecureTransport" = "true" } } },
      { Effect = "Allow"; Action = ["kms:GenerateDataKey", "kms:Decrypt"]; Resource = [aws_kms_key.secops.arn] }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cross_vpc_secops" {
  role       = aws_iam_role.cross_vpc_role.name
  policy_arn = aws_iam_policy.cross_vpc_secops.arn
}

###############################################################################
# S3 SECOPS LOG BUCKET
###############################################################################

resource "aws_s3_bucket" "secops_logs" {
  bucket        = "${var.project_name}-secops-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
  tags          = { Name = "${var.project_name}-secops-logs" }
}

resource "aws_s3_bucket_versioning" "secops_logs" {
  bucket = aws_s3_bucket.secops_logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secops_logs" {
  bucket = aws_s3_bucket.secops_logs.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "aws:kms"; kms_master_key_id = aws_kms_key.secops.arn }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "secops_logs" {
  bucket                  = aws_s3_bucket.secops_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "secops_logs_https_only" {
  bucket = aws_s3_bucket.secops_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Sid = "DenyNonHTTPS"; Effect = "Deny"; Principal = "*"; Action = "s3:*"; Resource = [aws_s3_bucket.secops_logs.arn, "${aws_s3_bucket.secops_logs.arn}/*"]; Condition = { Bool = { "aws:SecureTransport" = "false" } } }]
  })
}

resource "aws_s3_bucket_lifecycle_configuration" "secops_logs" {
  bucket = aws_s3_bucket.secops_logs.id
  rule {
    id     = "archive-old-logs"
    status = "Enabled"
    transition { days = 30; storage_class = "STANDARD_IA" }
    transition { days = 90; storage_class = "GLACIER" }
    expiration { days = 365 }
  }
}

###############################################################################
# KINESIS FIREHOSE
###############################################################################

resource "aws_iam_role" "firehose" {
  name = "${var.project_name}-firehose-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow"; Principal = { Service = "firehose.amazonaws.com" }; Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_policy" "firehose" {
  name = "${var.project_name}-firehose-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow"; Action = ["s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket", "s3:PutObject"]; Resource = [aws_s3_bucket.secops_logs.arn, "${aws_s3_bucket.secops_logs.arn}/*"] },
      { Effect = "Allow"; Action = ["es:DescribeElasticsearchDomain", "es:DescribeElasticsearchDomains", "es:DescribeElasticsearchDomainConfig", "es:ESHttpPost", "es:ESHttpPut"]; Resource = [aws_opensearch_domain.siem.arn, "${aws_opensearch_domain.siem.arn}/*"] },
      { Effect = "Allow"; Action = ["kms:GenerateDataKey", "kms:Decrypt"]; Resource = [aws_kms_key.secops.arn] },
      { Effect = "Allow"; Action = ["logs:PutLogEvents"]; Resource = "*" }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "firehose" {
  role       = aws_iam_role.firehose.name
  policy_arn = aws_iam_policy.firehose.arn
}

resource "aws_kinesis_firehose_delivery_stream" "logs_to_opensearch" {
  name        = "${var.project_name}-logs-to-opensearch"
  destination = "opensearch"

  opensearch_configuration {
    domain_arn            = aws_opensearch_domain.siem.arn
    role_arn              = aws_iam_role.firehose.arn
    index_name            = "secops-logs"
    index_rotation_period = "OneWeek"
    s3_backup_mode        = "AllDocuments"
    s3_configuration {
      role_arn           = aws_iam_role.firehose.arn
      bucket_arn         = aws_s3_bucket.secops_logs.arn
      prefix             = "firehose-backup/"
      compression_format = "GZIP"
    }
    retry_duration = 300
    processing_configuration {
      enabled = true
      processors {
        type = "Lambda"
        parameters { parameter_name = "LambdaArn"; parameter_value = "${aws_lambda_function.log_enrichment.arn}:$LATEST" }
      }
    }
  }

  tags = { Name = "${var.project_name}-firehose" }
}

###############################################################################
# OPENSEARCH SIEM
###############################################################################

resource "aws_security_group" "opensearch" {
  name        = "${var.project_name}-sg-opensearch"
  description = "OpenSearch: inbound only from hub VPC"
  vpc_id      = aws_vpc.hub.id
  ingress { from_port = 443; to_port = 443; protocol = "tcp"; cidr_blocks = [var.hub_vpc_cidr] }
  egress  { from_port = 0;   to_port = 0;   protocol = "-1"; cidr_blocks = ["0.0.0.0/0"] }
  tags = { Name = "${var.project_name}-sg-opensearch" }
}

resource "aws_opensearch_domain" "siem" {
  domain_name    = "${var.project_name}-siem"
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type          = var.opensearch_instance_type
    instance_count         = 2
    zone_awareness_enabled = true
    zone_awareness_config  { availability_zone_count = 2 }
  }

  ebs_options { ebs_enabled = true; volume_size = var.opensearch_volume_size; volume_type = "gp3"; throughput = 125 }

  vpc_options {
    subnet_ids         = aws_subnet.hub[*].id
    security_group_ids = [aws_security_group.opensearch.id]
  }

  encrypt_at_rest           { enabled = true; kms_key_id = aws_kms_key.secops.id }
  node_to_node_encryption   { enabled = true }
  domain_endpoint_options   { enforce_https = true; tls_security_policy = "Policy-Min-TLS-1-2-2019-07" }

  advanced_security_options {
    enabled                        = true
    anonymous_auth_enabled         = false
    internal_user_database_enabled = true
    master_user_options { master_user_name = "secops-admin"; master_user_password = "CHANGE_ME_OPENSEARCH_ADMIN" }
  }

  log_publishing_options { cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch.arn; log_type = "INDEX_SLOW_LOGS" }
  log_publishing_options { cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch.arn; log_type = "SEARCH_SLOW_LOGS" }
  log_publishing_options { cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch.arn; log_type = "ES_APPLICATION_LOGS" }

  tags = { Name = "${var.project_name}-opensearch-siem" }
}

resource "aws_cloudwatch_log_group" "opensearch" {
  name              = "/aws/opensearch/${var.project_name}"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.secops.arn
  tags              = { Name = "${var.project_name}-opensearch-logs" }
}

resource "aws_opensearch_domain_policy" "siem" {
  domain_name = aws_opensearch_domain.siem.domain_name
  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow"; Principal = { AWS = aws_iam_role.firehose.arn }; Action = ["es:ESHttpPost", "es:ESHttpPut"]; Resource = "${aws_opensearch_domain.siem.arn}/*" }]
  })
}

###############################################################################
# LAMBDA — LOG ENRICHMENT
###############################################################################

resource "aws_iam_role" "log_enrichment" {
  name = "${var.project_name}-log-enrichment-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow"; Principal = { Service = "lambda.amazonaws.com" }; Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "log_enrichment_basic" {
  role       = aws_iam_role.log_enrichment.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "archive_file" "log_enrichment" {
  type        = "zip"
  output_path = "/tmp/${var.project_name}-log-enrichment.zip"
  source {
    filename = "index.py"
    content  = <<-PYTHON
import json, base64, gzip, os, time

ACCOUNT_ID = os.environ.get('ACCOUNT_ID', 'unknown')
REGION     = os.environ.get('AWS_REGION', 'unknown')
PROJECT    = os.environ.get('PROJECT_NAME', 'unknown')

def handler(event, context):
    output = []
    for record in event['records']:
        payload = base64.b64decode(record['data'])
        try:
            data = json.loads(payload)
        except Exception:
            try:
                data = json.loads(gzip.decompress(payload))
            except Exception:
                data = {'raw': payload.decode('utf-8', errors='replace')}

        data['_meta'] = {
            'account_id' : ACCOUNT_ID,
            'region'     : REGION,
            'project'    : PROJECT,
            'ingested_at': int(time.time())
        }

        enriched = json.dumps(data).encode('utf-8')
        output.append({
            'recordId': record['recordId'],
            'result'  : 'Ok',
            'data'    : base64.b64encode(enriched).decode('utf-8')
        })
    return {'records': output}
PYTHON
  }
}

resource "aws_lambda_function" "log_enrichment" {
  function_name    = "${var.project_name}-log-enrichment"
  role             = aws_iam_role.log_enrichment.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  timeout          = 60
  filename         = data.archive_file.log_enrichment.output_path
  source_code_hash = data.archive_file.log_enrichment.output_base64sha256
  environment {
    variables = { ACCOUNT_ID = data.aws_caller_identity.current.account_id; PROJECT_NAME = var.project_name }
  }
  tags = { Name = "${var.project_name}-log-enrichment" }
}

###############################################################################
# LAMBDA — INCIDENT RESPONSE
###############################################################################

resource "aws_iam_role" "incident_response" {
  name = "${var.project_name}-incident-response-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow"; Principal = { Service = "lambda.amazonaws.com" }; Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_policy" "incident_response" {
  name = "${var.project_name}-incident-response-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow"; Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]; Resource = "arn:aws:logs:*:*:*" },
      { Effect = "Allow"; Action = ["ec2:StopInstances", "ec2:CreateTags", "ec2:DescribeInstances"]; Resource = "*" },
      { Effect = "Allow"; Action = ["sns:Publish"]; Resource = [aws_sns_topic.secops_alerts.arn] },
      { Effect = "Allow"; Action = ["guardduty:GetFindings"]; Resource = "*" },
      { Effect = "Allow"; Action = ["securityhub:UpdateFindings"]; Resource = "*" }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "incident_response" {
  role       = aws_iam_role.incident_response.name
  policy_arn = aws_iam_policy.incident_response.arn
}

data "archive_file" "incident_response" {
  type        = "zip"
  output_path = "/tmp/${var.project_name}-incident-response.zip"
  source {
    filename = "index.py"
    content  = <<-PYTHON
import json, boto3, os, logging
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client('ec2')
sns = boto3.client('sns')
SNS_ARN = os.environ['SNS_TOPIC_ARN']
PROJECT = os.environ['PROJECT_NAME']

def quarantine_instance(instance_id, finding_type, severity):
    try:
        ec2.stop_instances(InstanceIds=[instance_id])
        ec2.create_tags(Resources=[instance_id], Tags=[
            {'Key': 'SecurityStatus',    'Value': 'QUARANTINED'},
            {'Key': 'QuarantineTime',    'Value': datetime.utcnow().isoformat()},
            {'Key': 'QuarantineReason',  'Value': finding_type[:128]},
            {'Key': 'QuarantineSeverity','Value': str(severity)}
        ])
        logger.info(f"Quarantined instance {instance_id}")
        return True
    except Exception as e:
        logger.error(f"Failed to quarantine {instance_id}: {e}")
        return False

def send_alert(subject, message):
    sns.publish(TopicArn=SNS_ARN, Subject=subject, Message=message)

def handler(event, context):
    detail       = event.get('detail', {})
    severity     = float(detail.get('severity', 0))
    finding_type = detail.get('type', 'unknown')

    if severity < 7.0:
        return {'status': 'monitored', 'action': 'none'}

    actions = []
    instance_id = (detail.get('resource', {}).get('instanceDetails', {}).get('instanceId'))

    if instance_id:
        if quarantine_instance(instance_id, finding_type, severity):
            actions.append(f"QUARANTINED instance: {instance_id}")

    send_alert(
        subject=f"[{PROJECT}] CRITICAL AUTO-RESPONSE — {finding_type}",
        message=(
            f"AUTOMATED INCIDENT RESPONSE TRIGGERED\n"
            f"Severity   : {severity}\n"
            f"Finding    : {finding_type}\n"
            f"Instance   : {instance_id or 'N/A'}\n"
            f"Time       : {datetime.utcnow().isoformat()}Z\n"
            f"Actions    : {'; '.join(actions) or 'Alert only'}\n"
            f"Project    : {PROJECT}"
        )
    )

    return {'status': 'responded', 'actions': actions, 'severity': severity}
PYTHON
  }
}

resource "aws_lambda_function" "incident_response" {
  function_name    = "${var.project_name}-incident-response"
  role             = aws_iam_role.incident_response.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  timeout          = 60
  filename         = data.archive_file.incident_response.output_path
  source_code_hash = data.archive_file.incident_response.output_base64sha256
  environment {
    variables = { SNS_TOPIC_ARN = aws_sns_topic.secops_alerts.arn; PROJECT_NAME = var.project_name }
  }
  tags = { Name = "${var.project_name}-incident-response" }
}

resource "aws_cloudwatch_log_group" "incident_response" {
  name              = "/aws/lambda/${aws_lambda_function.incident_response.function_name}"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.secops.arn
  tags              = { Name = "${var.project_name}-incident-lambda-logs" }
}

###############################################################################
# EVENTBRIDGE
###############################################################################

resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name          = "${var.project_name}-guardduty-high"
  description   = "HIGH/CRITICAL GuardDuty findings → incident response Lambda"
  event_pattern = jsonencode({ source = ["aws.guardduty"]; detail-type = ["GuardDuty Finding"]; detail = { severity = [{ numeric = [">=", 7] }] } })
  tags = { Name = "${var.project_name}-guardduty-event-rule" }
}

resource "aws_cloudwatch_event_target" "incident_response" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "IncidentResponseLambda"
  arn       = aws_lambda_function.incident_response.arn
}

resource "aws_lambda_permission" "guardduty_invoke" {
  statement_id  = "AllowGuardDutyEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.incident_response.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_findings.arn
}

resource "aws_cloudwatch_event_rule" "securityhub_critical" {
  name          = "${var.project_name}-securityhub-critical"
  description   = "Security Hub CRITICAL findings → incident response"
  event_pattern = jsonencode({ source = ["aws.securityhub"]; detail-type = ["Security Hub Findings - Imported"]; detail = { findings = { Severity = { Label = ["CRITICAL", "HIGH"] } } } })
  tags = { Name = "${var.project_name}-securityhub-event-rule" }
}

resource "aws_cloudwatch_event_target" "securityhub_incident" {
  rule      = aws_cloudwatch_event_rule.securityhub_critical.name
  target_id = "IncidentResponseLambdaSH"
  arn       = aws_lambda_function.incident_response.arn
}

resource "aws_lambda_permission" "securityhub_invoke" {
  statement_id  = "AllowSecurityHubEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.incident_response.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.securityhub_critical.arn
}

###############################################################################
# SNS
###############################################################################

resource "aws_sns_topic" "secops_alerts" {
  name              = "${var.project_name}-alerts"
  kms_master_key_id = aws_kms_key.secops.id
  tags              = { Name = "${var.project_name}-alerts" }
}

resource "aws_sns_topic_subscription" "secops_email" {
  topic_arn = aws_sns_topic.secops_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

###############################################################################
# CLOUDWATCH
###############################################################################

resource "aws_cloudwatch_log_group" "secops_app" {
  name              = "/secops/${var.project_name}/events"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.secops.arn
  tags              = { Name = "${var.project_name}-secops-events" }
}

resource "aws_cloudwatch_metric_alarm" "rejected_traffic_spike" {
  alarm_name          = "${var.project_name}-rejected-traffic-spike"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "RejectedConnectionCount"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Sum"
  threshold           = 100
  alarm_description   = "Spike in rejected connections — potential scan or lateral movement"
  alarm_actions       = [aws_sns_topic.secops_alerts.arn]
  treat_missing_data  = "notBreaching"
  tags                = { Name = "${var.project_name}-rejected-traffic-alarm" }
}

resource "aws_cloudwatch_metric_alarm" "root_account_usage" {
  alarm_name          = "${var.project_name}-root-account-usage"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  threshold           = 0
  alarm_description   = "Root account API call detected — investigate immediately"
  alarm_actions       = [aws_sns_topic.secops_alerts.arn]
  treat_missing_data  = "notBreaching"
  metric_query {
    id          = "root_usage"
    return_data = true
    metric {
      metric_name = "CallCount"
      namespace   = "CloudTrailMetrics"
      period      = 300
      stat        = "Sum"
      dimensions  = { RootAccess = "true" }
    }
  }
  tags = { Name = "${var.project_name}-root-usage-alarm" }
}

resource "aws_cloudwatch_dashboard" "secops" {
  dashboard_name = "${var.project_name}-secops-operations"
  dashboard_body = jsonencode({
    widgets = [
      { type = "metric"; width = 12; height = 6; properties = { title = "GuardDuty Finding Severity"; metrics = [["AWS/GuardDuty", "FindingCount", "DetectorId", aws_guardduty_detector.secops.id, "Severity", "High"], [".", ".", ".", aws_guardduty_detector.secops.id, "Severity", "Medium"]]; period = 300; stat = "Sum"; view = "timeSeries"; region = var.aws_region } },
      { type = "metric"; width = 12; height = 6; properties = { title = "Security Hub Findings"; metrics = [["AWS/SecurityHub", "Findings", "ComplianceStatus", "FAILED", "RecordState", "ACTIVE"]]; period = 300; stat = "Sum"; view = "timeSeries"; region = var.aws_region } },
      { type = "metric"; width = 12; height = 6; properties = { title = "CloudTrail: API Error Rate"; metrics = [["AWS/CloudTrail", "ErrorCount"]]; period = 300; stat = "Sum"; view = "timeSeries"; region = var.aws_region } }
    ]
  })
}

###############################################################################
# OUTPUTS
###############################################################################

output "transit_gateway_id"       { value = aws_ec2_transit_gateway.hub.id }
output "hub_vpc_id"               { value = aws_vpc.hub.id }
output "prod_vpc_id"              { value = aws_vpc.production.id }
output "dev_vpc_id"               { value = aws_vpc.development.id }
output "staging_vpc_id"           { value = aws_vpc.staging.id }
output "opensearch_endpoint"      { value = aws_opensearch_domain.siem.endpoint }
output "opensearch_dashboard_url" { value = "https://${aws_opensearch_domain.siem.endpoint}/_dashboards" }
output "secops_log_bucket"        { value = aws_s3_bucket.secops_logs.bucket }
output "cloudtrail_bucket"        { value = aws_s3_bucket.cloudtrail.bucket }
output "cross_vpc_role_arn"       { value = aws_iam_role.cross_vpc_role.arn }
output "kms_key_id"               { value = aws_kms_key.secops.key_id }
output "kms_key_arn"              { value = aws_kms_key.secops.arn }
output "sns_alerts_arn"           { value = aws_sns_topic.secops_alerts.arn }
output "guardduty_detector_id"    { value = aws_guardduty_detector.secops.id }
output "firehose_stream_name"     { value = aws_kinesis_firehose_delivery_stream.logs_to_opensearch.name }
output "cw_dashboard"             { value = "https://console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${var.project_name}-secops-operations" }
