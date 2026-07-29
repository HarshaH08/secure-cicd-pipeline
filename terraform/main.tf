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
resource "aws_s3_bucket" "artifacts" {
  # ACCEPTED RISK (CKV2_AWS_62): no event notification configured. This bucket
  # holds CI build artifacts, not a data pipeline needing near-real-time
  # triggers on new objects — there is no downstream consumer to notify.
  #checkov:skip=CKV2_AWS_62:CI artifact bucket has no event-driven consumer
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

resource "aws_s3_bucket" "access_logs" {
  #checkov:skip=CKV2_AWS_62:Log bucket has no event-driven consumer; alerting runs through CloudWatch metric filters instead
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

# FIX (CKV_AWS_21): the artifacts bucket had versioning but the log bucket did
# not. Versioning matters MORE here — it makes deletion of audit evidence
# recoverable, which is exactly what an attacker covering their tracks would
# attempt.
resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration { status = "Enabled" }
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

  # FIX (CKV_AWS_300): failed multipart uploads leave orphaned parts that are
  # invisible in the console but bill indefinitely. Aborting after 7 days is
  # both a cost control and a hygiene measure.
  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
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

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
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

resource "aws_iam_policy" "cicd" {
  name   = "${var.project_name}-cicd-policy-${var.environment}"
  policy = data.aws_iam_policy_document.cicd_permissions.json
}

resource "aws_iam_role_policy_attachment" "cicd" {
  role       = aws_iam_role.cicd.name
  policy_arn = aws_iam_policy.cicd.arn
}

# ─────────────────────────────────────────────
# Detection pipeline — CloudTrail → CloudWatch Logs → metric filter → alarm → SNS
#
# S3 delivery alone is durable storage, not detection: logs land every ~5-15
# minutes and nothing reads them. Routing to CloudWatch Logs makes the events
# queryable in near-real-time and lets metric filters fire alarms on specific
# patterns. That is the difference between having logs and having detections.
# ─────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${var.project_name}-${var.environment}"
  retention_in_days = 365 # audit retention; also satisfies CKV_AWS_338
  kms_key_id        = aws_kms_key.s3.arn
}

# Role CloudTrail assumes to write into the log group
resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name               = "${var.project_name}-cloudtrail-cw-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume.json
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name   = "${var.project_name}-cloudtrail-cw-${var.environment}"
  role   = aws_iam_role.cloudtrail_cloudwatch.id
  policy = data.aws_iam_policy_document.cloudtrail_cloudwatch.json
}

# SNS topic for alarm notifications
resource "aws_sns_topic" "security_alerts" {
  name              = "${var.project_name}-security-alerts-${var.environment}"
  kms_master_key_id = aws_kms_key.s3.id # CKV_AWS_26: encrypt topic at rest
}

# ── Detection 1: someone disabled audit logging ──
# Attackers commonly stop or delete the trail before acting. This is one of
# the highest-signal, lowest-noise detections available in AWS.
resource "aws_cloudwatch_log_metric_filter" "logging_disabled" {
  name           = "cloudtrail-logging-disabled"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.eventName = StopLogging) || ($.eventName = DeleteTrail) || ($.eventName = UpdateTrail) }"

  metric_transformation {
    name      = "CloudTrailLoggingDisabled"
    namespace = "SecurityDetections"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "logging_disabled" {
  alarm_name          = "${var.project_name}-cloudtrail-logging-disabled-${var.environment}"
  alarm_description   = "CloudTrail logging was stopped, deleted, or modified. Investigate immediately — this is a common precursor to further attacker activity."
  metric_name         = "CloudTrailLoggingDisabled"
  namespace           = "SecurityDetections"
  statistic           = "Sum"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  period              = 300
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

# ── Detection 2: S3 public access protections removed ──
resource "aws_cloudwatch_log_metric_filter" "s3_public_access" {
  name           = "s3-public-access-block-removed"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.eventName = DeletePublicAccessBlock) || ($.eventName = PutBucketPublicAccessBlock) || ($.eventName = PutBucketPolicy) }"

  metric_transformation {
    name      = "S3PublicAccessChange"
    namespace = "SecurityDetections"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "s3_public_access" {
  alarm_name          = "${var.project_name}-s3-public-access-change-${var.environment}"
  alarm_description   = "S3 public access configuration changed. Verify the bucket is not now publicly readable."
  metric_name         = "S3PublicAccessChange"
  namespace           = "SecurityDetections"
  statistic           = "Sum"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  period              = 300
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

# ── Detection 3: unexpected OIDC role assumption ──
# Catches a repo other than the expected one assuming the CI role — the
# failure mode the trust policy's sub condition is designed to prevent.
resource "aws_cloudwatch_log_metric_filter" "unexpected_oidc" {
  name           = "unexpected-oidc-assumption"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.eventName = AssumeRoleWithWebIdentity) && ($.errorCode = \"AccessDenied\") }"

  metric_transformation {
    name      = "DeniedOIDCAssumption"
    namespace = "SecurityDetections"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "unexpected_oidc" {
  alarm_name          = "${var.project_name}-denied-oidc-assumption-${var.environment}"
  alarm_description   = "A federated identity was denied assumption of the CI role. Repeated failures may indicate an attempt to abuse the OIDC trust relationship from an unauthorized repository."
  metric_name         = "DeniedOIDCAssumption"
  namespace           = "SecurityDetections"
  statistic           = "Sum"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 3
  period              = 300
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
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

  # CKV2_AWS_10 — near-real-time delivery for metric filters and alarms
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch.arn

  # CKV_AWS_252 — notification target for trail delivery
  sns_topic_name = aws_sns_topic.security_alerts.name

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
data "aws_region" "current" {}
