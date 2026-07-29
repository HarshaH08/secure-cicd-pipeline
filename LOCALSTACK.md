# Testing this Terraform locally with LocalStack

LocalStack runs an AWS API emulator in a Docker container. Terraform talks to it exactly as it
would talk to real AWS — same commands, same state mechanics — but nothing leaves your machine
and nothing costs money.

## Coverage caveat (read first)

The free tier does **not** emulate every service this project uses:

| Service | Free tier | Notes |
|---|---|---|
| S3 | Yes | Buckets, versioning, encryption config, public access blocks |
| IAM | Yes | Roles, policies, OIDC provider (policy *enforcement* is a paid feature) |
| STS | Yes | |
| KMS | Yes | Keys, aliases, rotation |
| ECR | No | Paid tier |
| CloudTrail | No | Paid tier |

So the plan is: **apply the S3 / KMS / IAM core against LocalStack**, and validate the ECR and
CloudTrail resources statically with `terraform validate` and Checkov. That's an honest and
defensible testing story — and knowing which parts of your infra you *can't* integration-test
locally is itself a real engineering observation worth mentioning in an interview.

---

## Setup (Windows / PowerShell)

### 1. Prerequisites
- Docker Desktop installed and running
- Python 3 and pip
- Terraform (`winget install HashiCorp.Terraform`)

### 2. Install the tooling
```powershell
pip install localstack awscli-local terraform-local
```
- `localstack` — the CLI that starts/stops the container
- `awslocal` — the AWS CLI pointed at LocalStack instead of real AWS
- `tflocal` — a thin Terraform wrapper that auto-injects LocalStack endpoints, so you don't have
  to hand-write a provider override block

### 3. Start it
```powershell
localstack start -d
localstack status services
```
You should see a list of services and their status. LocalStack listens on `localhost:4566`.

---

## Running Terraform against it

### 1. Initialize with local state
The `backend "s3"` block points at real AWS. For local testing, skip it entirely:
```powershell
cd terraform
tflocal init -backend=false
```

### 2. Validate everything (all resources, no cloud calls)
```powershell
tflocal validate
```
This catches syntax errors, bad references, and type mismatches across the whole config —
including the ECR and CloudTrail resources LocalStack can't create.

### 3. Plan
```powershell
tflocal plan -var="environment=dev"
```

### 4. Apply only the supported resources
Targeted apply, since ECR and CloudTrail aren't emulated on the free tier:
```powershell
tflocal apply `
  -var="environment=dev" `
  -target=aws_kms_key.s3 `
  -target=aws_kms_alias.s3 `
  -target=aws_s3_bucket.artifacts `
  -target=aws_s3_bucket.access_logs `
  -target=aws_s3_bucket_versioning.artifacts `
  -target=aws_s3_bucket_server_side_encryption_configuration.artifacts `
  -target=aws_s3_bucket_server_side_encryption_configuration.access_logs `
  -target=aws_s3_bucket_public_access_block.artifacts `
  -target=aws_s3_bucket_public_access_block.access_logs `
  -target=aws_iam_openid_connect_provider.github `
  -target=aws_iam_role.cicd `
  -target=aws_iam_policy.cicd `
  -target=aws_iam_role_policy_attachment.cicd
```

### 5. Verify the resources actually exist
```powershell
awslocal s3 ls
awslocal s3api get-bucket-encryption --bucket <bucket-name-from-output>
awslocal s3api get-public-access-block --bucket <bucket-name-from-output>
awslocal kms list-keys
awslocal kms get-key-rotation-status --key-id <key-id>
awslocal iam list-roles
awslocal iam get-role --role-name secure-cicd-cicd-role-dev
```

This is the payoff: you're confirming with the AWS API itself that encryption is on, public
access is blocked, and key rotation is enabled — not just trusting that the Terraform said so.

### 6. Tear down
```powershell
tflocal destroy -var="environment=dev"
localstack stop
```

---

## Prove the security controls actually work

Validating that infrastructure gets created is table stakes. Validating that the *guardrails*
catch bad infrastructure is the more interesting exercise, and gives you something concrete to
talk about.

### Test 1 — does the OPA policy catch a public bucket?
Temporarily add to `main.tf`:
```hcl
resource "aws_s3_bucket" "oops" {
  bucket = "deliberately-bad-bucket-test"
}

resource "aws_s3_bucket_public_access_block" "oops" {
  bucket                  = aws_s3_bucket.oops.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
```
Then:
```powershell
tflocal plan -var="environment=dev" -out=tfplan.binary
tflocal show -json tfplan.binary > tfplan.json
conftest test tfplan.json --policy ../policies/ --namespace terraform.security
```
Expect a `POLICY VIOLATION [S3-001]` per unset field. **Remove the test resource afterward.**

### Test 2 — does Gitleaks catch a secret?
```powershell
echo 'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"' > test-secret.py
docker run -v ${PWD}:/repo zricethezav/gitleaks:latest detect --source /repo -v
del test-secret.py
```
That's AWS's own published example key, so it's safe to use as a test string.

### Test 3 — does Trivy catch a vulnerable base image?
Temporarily change the Dockerfile base to something knowingly old (e.g. `python:3.6-slim`),
build, scan, and confirm CRITICAL/HIGH findings appear. Then revert.

Screenshot each of these. "I tested my controls adversarially" is a much stronger claim than
"I set up scanners," and almost nobody at the intern level does it.

---

## Alternatives if LocalStack's free tier is too limiting

- **Ministack** — a newer MIT-licensed emulator that claims free ECR and CloudTrail support.
  It's very new, so treat it as experimental rather than a reliable base.
- **GitHub Student Developer Pack / AWS Educate** — worth checking for student cloud credits
  before paying for anything.
