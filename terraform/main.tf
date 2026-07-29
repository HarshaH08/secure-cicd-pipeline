terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Remote state with encryption and locking.
  # NOTE: backend blocks CANNOT contain variables or interpolation — Terraform
  # reads this before variables are evaluated. Values are supplied at init time
  # via partial configuration:
  #   terraform init -backend-config=backend-dev.hcl
  backend "s3" {}
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
# ACCEPTED RISK (CKV2_AWS_62): no event notification configured. This bucket
# holds CI build artifacts, not a data pipeline needing near-real-time
# triggers on new objects — there's no downstream consumer to notify.
#checkov:skip=CKV2_AWS_62:CI artifact bucket has no event-driven consumer
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

#checkov:skip=CKV2_AWS_62:Log bucket has no event-driven consumer in this environment
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

# FIX: this was missing — Checkov (CKV_AWS_145) correctly caught that the
# access_logs bucket had no encryption config, unlike the artifacts bucket.
resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}

# FIX: lifecycle rules (CKV2_AWS_61) — expire old noncurrent versions so
# storage costs don't grow forever and stale data doesn't linger.
resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    id     = "expire-noncurrent-versions"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    id     = "expire-old-logs"
    status = "Enabled"
    expiration {
      days = 365 # audit logs kept 1 year, then expired
    }
  }
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
  # FIX: Checkov (CKV2_AWS_64) caught that this key had no explicit policy,
  # unlike the S3 key below. Without one, AWS applies a permissive default
  # key policy — better to state access explicitly.
  policy = data.aws_iam_policy_document.kms_ecr.json
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

# ACCEPTED RISK (CKV_AWS_356, CKV_AWS_109, CKV_AWS_111):
# Checkov flags the wildcard Resource on the ECRAuth statement inside this
# policy. That statement grants ONLY ecr:GetAuthorizationToken, which per
# AWS's own IAM reference does not support resource-level permissions and
# must use "*": https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonelasticcontainerregistry.html
# Every other statement in cicd_permissions.json is scoped to a specific
# resource ARN. Confirmed false positive — documenting instead of suppressing
# silently, per the JD's "triage and track findings to closure."
#checkov:skip=CKV_AWS_356:GetAuthorizationToken requires Resource="*" — no resource-level permissions exist for this action
#checkov:skip=CKV_AWS_109:Same statement as above; token generation only, no permissions-management action granted
#checkov:skip=CKV_AWS_111:Same statement as above; not a write action, all real write actions below are scoped to specific ARNs
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
# ACCEPTED RISK (CKV_AWS_252): Checkov wants an SNS topic wired to this
# trail for real-time alerting. Skipped for this portfolio project to avoid
# an always-on SNS resource with no subscriber. In production this would
# route to the org's SIEM (e.g. Splunk/Datadog) via a log pipeline instead
# of a bare SNS topic — noting the gap rather than adding an unused resource.
#checkov:skip=CKV_AWS_252:No SNS subscriber in this environment; would route to SIEM in production
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
