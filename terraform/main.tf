terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Remote state with encryption and locking
  backend "s3" {
    bucket         = "notable-tfstate-${var.environment}"
    key            = "secure-pipeline/terraform.tfstate"
    region         = var.aws_region
    encrypt        = true
    dynamodb_table = "tf-state-lock"
    kms_key_id     = "alias/terraform-state"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "secure-cicd-pipeline"
      Environment = var.environment
      Owner       = "security-eng"
      ManagedBy   = "terraform"
    }
  }
}

# ─────────────────────────────────────────────
# ECR — container image registry
# ─────────────────────────────────────────────
resource "aws_ecr_repository" "app" {
  name                 = "${var.project_name}-${var.environment}"
  image_tag_mutability = "IMMUTABLE" # prevent tag overwriting

  image_scanning_configuration {
    scan_on_push = true # automatic vuln scan on every push
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr.arn
  }
}

resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep only last 10 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}

# ─────────────────────────────────────────────
# S3 — artifact storage (secure by default)
# ─────────────────────────────────────────────
resource "aws_s3_bucket" "artifacts" {
  bucket        = "${var.project_name}-artifacts-${var.environment}-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "artifacts" {
  bucket        = aws_s3_bucket.artifacts.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "artifacts/"
}

# Separate access log bucket
resource "aws_s3_bucket" "access_logs" {
  bucket        = "${var.project_name}-access-logs-${var.environment}-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ─────────────────────────────────────────────
# KMS keys
# ─────────────────────────────────────────────
resource "aws_kms_key" "s3" {
  description             = "KMS key for S3 artifact encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_s3.json
}

resource "aws_kms_alias" "s3" {
  name          = "alias/${var.project_name}-s3-${var.environment}"
  target_key_id = aws_kms_key.s3.key_id
}

resource "aws_kms_key" "ecr" {
  description             = "KMS key for ECR image encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "ecr" {
  name          = "alias/${var.project_name}-ecr-${var.environment}"
  target_key_id = aws_kms_key.ecr.key_id
}

# ─────────────────────────────────────────────
# IAM — least-privilege CI/CD role
# ─────────────────────────────────────────────
resource "aws_iam_role" "cicd" {
  name               = "${var.project_name}-cicd-role-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.cicd_assume.json
  max_session_duration = 3600 # 1 hour max

  tags = { Purpose = "github-actions-cicd" }
}

resource "aws_iam_policy" "cicd" {
  name   = "${var.project_name}-cicd-policy-${var.environment}"
  policy = data.aws_iam_policy_document.cicd_permissions.json
}

resource "aws_iam_role_policy_attachment" "cicd" {
  role       = aws_iam_role.cicd.name
  policy_arn = aws_iam_policy.cicd.arn
}

# ─────────────────────────────────────────────
# CloudTrail — audit logging
# ─────────────────────────────────────────────
resource "aws_cloudtrail" "pipeline" {
  name                          = "${var.project_name}-audit-trail-${var.environment}"
  s3_bucket_name                = aws_s3_bucket.access_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true # detect log tampering
  kms_key_id                    = aws_kms_key.s3.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.artifacts.arn}/"]
    }
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
