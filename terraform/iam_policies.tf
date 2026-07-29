# ─────────────────────────────────────────────
# OIDC Trust — GitHub Actions assumes role via
# short-lived OIDC tokens (no long-lived keys!)
# ─────────────────────────────────────────────
resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = ["sts.amazonaws.com"]

  # GitHub's OIDC thumbprint (rotate periodically)
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

data "aws_iam_policy_document" "cicd_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Scope to specific repo + branch (least privilege)
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_org}/${var.github_repo}:ref:refs/heads/main"]
    }
  }
}

# ─────────────────────────────────────────────
# CI/CD permissions — scoped to only what the
# pipeline actually needs (least privilege)
# ─────────────────────────────────────────────
data "aws_iam_policy_document" "cicd_permissions" {
  # ECR — push images only
  statement {
    sid    = "ECRAuth"
    effect = "Allow"
    actions = [
      "ecr:GetAuthorizationToken"
    ]
    resources = ["*"] # GetAuthorizationToken is account-level
  }

  statement {
    sid    = "ECRPush"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
      "ecr:PutImage",
      "ecr:DescribeImageScanFindings",
    ]
    resources = [aws_ecr_repository.app.arn]
  }

  # S3 — write artifacts only, no delete
  statement {
    sid    = "S3ArtifactWrite"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:ListBucket",
    ]
    resources = [
      aws_s3_bucket.artifacts.arn,
      "${aws_s3_bucket.artifacts.arn}/*",
    ]
  }

  # KMS — decrypt/encrypt for s3 + ecr only
  statement {
    sid    = "KMSAccess"
    effect = "Allow"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt",
    ]
    resources = [
      aws_kms_key.s3.arn,
      aws_kms_key.ecr.arn,
    ]
  }

  # Explicit deny — block any privilege escalation attempts
  statement {
    sid    = "DenyPrivilegeEscalation"
    effect = "Deny"
    actions = [
      "iam:CreateUser",
      "iam:AttachUserPolicy",
      "iam:AttachRolePolicy",
      "iam:PutUserPolicy",
      "iam:PutRolePolicy",
      "iam:CreateAccessKey",
      "iam:PassRole",
    ]
    resources = ["*"]
  }
}

# ─────────────────────────────────────────────
# KMS key policies — prevent key misuse
# ─────────────────────────────────────────────
# ─────────────────────────────────────────────
# CloudTrail → CloudWatch Logs delivery role
# ─────────────────────────────────────────────
data "aws_iam_policy_document" "cloudtrail_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "cloudtrail_cloudwatch" {
  # Scoped to this log group's streams only — no wildcard resource.
  statement {
    sid    = "WriteCloudTrailEvents"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.cloudtrail.arn}:*"]
  }
}

data "aws_iam_policy_document" "kms_ecr" {
  # ACCEPTED RISK — CONFIRMED FALSE POSITIVE (CKV_AWS_111, CKV_AWS_356, CKV_AWS_109)
  #
  # These checks apply identity-policy heuristics to a resource-based policy.
  # In a KMS *key policy*, Resource: "*" means "the key this policy is attached
  # to" — not "every key in the account." The wildcard is scoped by attachment,
  # so there is no over-permission to remove.
  #
  # The RootAccess statement granting kms:* to the account root is AWS's own
  # recommended default key policy. Removing it risks permanently orphaning the
  # key: with no principal able to modify the policy, the key and everything
  # encrypted under it become unrecoverable.
  # Ref: https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html
  #
  # Every non-root statement below is already restricted to a named principal
  # and the three minimum actions required for envelope encryption.
  #checkov:skip=CKV_AWS_111:KMS key policy — Resource "*" is scoped to the attached key, not all keys
  #checkov:skip=CKV_AWS_356:KMS key policy — resource-based, wildcard is inherent to the policy type
  #checkov:skip=CKV_AWS_109:Root access is the AWS-recommended default; removing it risks orphaning the key
  statement {
    sid     = "RootAccess"
    effect  = "Allow"
    actions = ["kms:*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    resources = ["*"]
  }

  statement {
    sid    = "CIServiceAccess"
    effect = "Allow"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.cicd.arn]
    }
    resources = ["*"]
  }

  # ECR needs to call KMS on push/pull for image layer encryption
  statement {
    sid    = "ECRServiceAccess"
    effect = "Allow"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    principals {
      type        = "Service"
      identifiers = ["ecr.amazonaws.com"]
    }
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "kms_s3" {
  # Same confirmed false positive as kms_ecr above — see that block for the
  # full reasoning on why Resource "*" in a KMS key policy is scoped to the
  # attached key rather than the whole account.
  #checkov:skip=CKV_AWS_111:KMS key policy — Resource "*" is scoped to the attached key, not all keys
  #checkov:skip=CKV_AWS_356:KMS key policy — resource-based, wildcard is inherent to the policy type
  #checkov:skip=CKV_AWS_109:Root access is the AWS-recommended default; removing it risks orphaning the key
  statement {
    sid     = "RootAccess"
    effect  = "Allow"
    actions = ["kms:*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    resources = ["*"]
  }

  statement {
    sid    = "CIServiceAccess"
    effect = "Allow"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.cicd.arn]
    }
    resources = ["*"]
  }

  # CloudWatch Logs encrypts the CloudTrail log group with this key. The
  # ArnLike condition scopes access to log groups in this account/region only,
  # rather than granting the service blanket use of the key. Written as a
  # literal ARN pattern rather than a resource reference to avoid a dependency
  # cycle: the log group needs the key, so the key policy cannot need the group.
  statement {
    sid    = "CloudWatchLogsAccess"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    principals {
      type        = "Service"
      identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
    }
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:*"]
    }
  }

  # CloudTrail writes encrypted objects to the log bucket and publishes to the
  # SNS topic, both of which use this key.
  statement {
    sid    = "CloudTrailAndSNSAccess"
    effect = "Allow"
    actions = [
      "kms:GenerateDataKey*",
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com", "sns.amazonaws.com"]
    }
    resources = ["*"]
  }
}

# S3 bucket policy for CloudTrail logging
data "aws_iam_policy_document" "cloudtrail_logs" {
  statement {
    sid     = "CloudTrailWrite"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = ["${aws_s3_bucket.access_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid     = "CloudTrailAcl"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = [aws_s3_bucket.access_logs.arn]
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.access_logs.id
  policy = data.aws_iam_policy_document.cloudtrail_logs.json
}

# ─────────────────────────────────────────────
# SNS topic policy — allow CloudTrail to publish
# ─────────────────────────────────────────────
data "aws_iam_policy_document" "sns_security_alerts" {
  statement {
    sid     = "AllowCloudTrailPublish"
    effect  = "Allow"
    actions = ["SNS:Publish"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = [aws_sns_topic.security_alerts.arn]
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid     = "AllowCloudWatchAlarmsPublish"
    effect  = "Allow"
    actions = ["SNS:Publish"]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    resources = [aws_sns_topic.security_alerts.arn]
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn    = aws_sns_topic.security_alerts.arn
  policy = data.aws_iam_policy_document.sns_security_alerts.json
}
