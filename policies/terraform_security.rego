# terraform_security.rego
# OPA/Conftest policy — enforces security guardrails on Terraform plans
# Run with: conftest test --policy policies/ plan.json
package terraform.security

import future.keywords.if
import future.keywords.in

# ─────────────────────────────────────────────
# RULE 1: S3 buckets must block all public access
# ─────────────────────────────────────────────
deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_public_access_block"
  values := resource.change.after

  some field in ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]
  values[field] == false

  msg := sprintf(
    "POLICY VIOLATION [S3-001]: S3 bucket public access block '%s' must have all four block fields set to true. Field '%s' is false.",
    [resource.address, field]
  )
}

# Warn if public access block resource is missing entirely
warn[msg] if {
  s3_buckets := {r.address | r := input.resource_changes[_]; r.type == "aws_s3_bucket"}
  pub_blocks := {r.address | r := input.resource_changes[_]; r.type == "aws_s3_bucket_public_access_block"}
  count(s3_buckets) > count(pub_blocks)

  msg := "POLICY WARNING [S3-002]: Found S3 buckets without a corresponding aws_s3_bucket_public_access_block resource."
}

# ─────────────────────────────────────────────
# RULE 2: S3 buckets must have encryption enabled
# ─────────────────────────────────────────────
deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket"

  # Check that a matching encryption config exists
  bucket_name := resource.name
  not any_encryption_for_bucket(bucket_name)

  msg := sprintf(
    "POLICY VIOLATION [S3-003]: S3 bucket '%s' has no server-side encryption configuration.",
    [resource.address]
  )
}

any_encryption_for_bucket(bucket_name) if {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_server_side_encryption_configuration"
  resource.change.after.bucket != null
}

# ─────────────────────────────────────────────
# RULE 3: ECR repos must scan images on push
# ─────────────────────────────────────────────
deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_ecr_repository"
  resource.change.after.image_scanning_configuration[_].scan_on_push == false

  msg := sprintf(
    "POLICY VIOLATION [ECR-001]: ECR repository '%s' must have scan_on_push = true.",
    [resource.address]
  )
}

# ─────────────────────────────────────────────
# RULE 4: ECR repos must use immutable tags
# ─────────────────────────────────────────────
deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_ecr_repository"
  resource.change.after.image_tag_mutability != "IMMUTABLE"

  msg := sprintf(
    "POLICY VIOLATION [ECR-002]: ECR repository '%s' must use IMMUTABLE image tags to prevent tag overwriting attacks.",
    [resource.address]
  )
}

# ─────────────────────────────────────────────
# RULE 5: KMS keys must have rotation enabled
# ─────────────────────────────────────────────
deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_kms_key"
  resource.change.after.enable_key_rotation != true

  msg := sprintf(
    "POLICY VIOLATION [KMS-001]: KMS key '%s' must have automatic key rotation enabled.",
    [resource.address]
  )
}

# ─────────────────────────────────────────────
# RULE 6: IAM roles must not use wildcard actions
# ─────────────────────────────────────────────
deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_policy"
  policy := json.unmarshal(resource.change.after.policy)
  statement := policy.Statement[_]
  statement.Effect == "Allow"
  statement.Action == "*"
  statement.Resource == "*"

  msg := sprintf(
    "POLICY VIOLATION [IAM-001]: IAM policy '%s' contains a wildcard allow (*:*) statement. Use least-privilege permissions.",
    [resource.address]
  )
}

# ─────────────────────────────────────────────
# RULE 7: CloudTrail must enable log validation
# ─────────────────────────────────────────────
deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudtrail"
  resource.change.after.enable_log_file_validation != true

  msg := sprintf(
    "POLICY VIOLATION [AUDIT-001]: CloudTrail '%s' must have log file validation enabled to detect tampering.",
    [resource.address]
  )
}

# ─────────────────────────────────────────────
# RULE 8: Resources must have required tags
# ─────────────────────────────────────────────
required_tags := {"Project", "Environment", "Owner", "ManagedBy"}

warn[msg] if {
  resource := input.resource_changes[_]
  resource.change.after.tags != null
  tags := resource.change.after.tags

  missing := required_tags - {t | tags[t]}
  count(missing) > 0

  msg := sprintf(
    "POLICY WARNING [TAG-001]: Resource '%s' is missing required tags: %v",
    [resource.address, missing]
  )
}
