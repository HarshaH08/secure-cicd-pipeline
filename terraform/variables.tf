variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (dev / staging / prod)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging, or prod."
  }
}

variable "project_name" {
  description = "Short project name used in resource naming"
  type        = string
  default     = "secure-cicd"
}

variable "github_org" {
  description = "GitHub org or username that owns the repo"
  type        = string
  default     = "HarshaH08"
}

variable "github_repo" {
  description = "GitHub repository name"
  type        = string
  default     = "secure-cicd-pipeline"
}
