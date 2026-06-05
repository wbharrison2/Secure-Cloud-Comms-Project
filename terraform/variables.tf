variable "aws_region" {
  description = "AWS region for primary resources"
  type        = string
  default     = "us-west-2"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "artisan-gem-works"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "eks_cluster_version" {
  description = "Kubernetes version for EKS cluster"
  type        = string
  default     = "1.29"
}

variable "app_node_instance_type" {
  description = "EC2 instance type for application node group"
  type        = string
  default     = "t3.medium"
}

variable "system_node_instance_type" {
  description = "EC2 instance type for system node group (ArgoCD, Istio, Falco)"
  type        = string
  default     = "t3.small"
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.medium"
}

variable "db_name" {
  description = "PostgreSQL database name"
  type        = string
  default     = "artisangemworks"
}

variable "alert_email" {
  description = "Email address for security alert notifications"
  type        = string
  default     = "security@artisangemworks.com"
}

variable "pagerduty_integration_url" {
  description = "PagerDuty integration URL for critical alerts"
  type        = string
  sensitive   = true
  default     = ""
}
