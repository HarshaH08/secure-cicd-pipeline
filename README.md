# Secure CI/CD Pipeline

A production-grade secure CI/CD pipeline built with **Terraform**, **GitHub Actions**, and **OPA/Conftest** — implementing shift-left security controls across the full software delivery lifecycle.

## Architecture

```
Developer pushes code
        │
        ▼
┌─────────────────────────────────────────────────────────┐
│  Pre-commit Hooks (local gate — fast feedback)          │
│  • Gitleaks  • Bandit  • terraform fmt  • Checkov       │
└──────────────────────────┬──────────────────────────────┘
                           │ git push
                           ▼
┌─────────────────────────────────────────────────────────┐
│  GitHub Actions CI Pipeline                             │
│                                                         │
│  [1] Secrets Scan (Gitleaks) ──────────────────────┐   │
│                                                     │   │
│  [2] SAST (Bandit) ──────────────────────────┐     │   │
│                                              │ All  │   │
│  [3] Dependency Scan (pip-audit + Safety) ───┤ must │   │
│                                              │ pass │   │
│  [4] IaC Policy Check (Conftest + Checkov) ──┤      │   │
│                                              │      │   │
│  [5] Container Build + Trivy Image Scan ─────┘      │   │
│           │                                         │   │
│           │ All gates pass                          │   │
│           ▼                                         │   │
│  [6] Push to ECR (OIDC — no long-lived AWS keys)   │   │
│       SLSA provenance + SBOM attestation            │   │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │  AWS (Terraform-built) │
              │  • ECR (immutable tags)│
              │  • S3 (KMS encrypted) │
              │  • CloudTrail (audit) │
              │  • IAM (least-priv)   │
              └────────────────────────┘
```

## Security Controls

### Shift-Left (Pre-commit + CI)
| Tool | Category | What it catches |
|------|----------|-----------------|
| Gitleaks | Secrets detection | API keys, tokens, passwords committed to git |
| Bandit | SAST | Python security anti-patterns (SQLi, hardcoded secrets, weak crypto) |
| pip-audit + Safety | Dependency scanning | CVEs in third-party packages |
| Checkov | IaC policy-as-code | Terraform misconfigurations (public S3, unencrypted resources) |
| Conftest + OPA | Policy-as-code | Custom Rego rules enforced on Terraform plan JSON |
| Trivy | Container scanning | CVEs in base images and OS packages |

### Cloud Security (Terraform-provisioned)
| Control | Implementation |
|---------|---------------|
| No long-lived AWS credentials | GitHub Actions assumes IAM role via OIDC (short-lived tokens) |
| Least-privilege IAM | CI/CD role scoped to ECR push + S3 write only; explicit `Deny` on `iam:PassRole` |
| Encryption at rest | S3 + ECR encrypted with customer-managed KMS keys; key rotation enabled |
| Audit logging | CloudTrail with log file integrity validation; logs to dedicated S3 bucket |
| Immutable image tags | ECR configured with `IMMUTABLE` tag mutability |
| Container hardening | Non-root user, multi-stage build, minimal runtime image |

## Repository Structure

```
.
├── terraform/
│   ├── main.tf           # ECR, S3, KMS, CloudTrail
│   ├── iam_policies.tf   # OIDC trust + least-privilege CI/CD role
│   ├── variables.tf
│   └── outputs.tf
├── policies/
│   └── terraform_security.rego  # OPA rules for IaC policy-as-code
├── app/
│   ├── app.py            # Flask app with security-by-default patterns
│   ├── Dockerfile        # Multi-stage, non-root, hardened
│   └── requirements.txt
├── .github/workflows/
│   └── secure-pipeline.yml  # Full CI/CD pipeline definition
├── .pre-commit-config.yaml
└── pyproject.toml        # Bandit configuration
```

## Setup

### 1. Deploy AWS Infrastructure
```bash
cd terraform
terraform init
terraform plan -var="environment=dev" -out=tfplan
terraform apply tfplan
```

### 2. Configure GitHub Secrets
```
AWS_CICD_ROLE_ARN   # output from terraform: cicd_role_arn
```

### 3. Install pre-commit hooks locally
```bash
pip install pre-commit
pre-commit install
# Test all hooks against current files:
pre-commit run --all-files
```

### 4. Push code — the pipeline runs automatically

## OPA Policy Enforcement

Custom Rego policies in `policies/` enforce:
- S3 public access blocking (all 4 fields required)
- S3 encryption required on all buckets
- ECR `scan_on_push = true`
- ECR immutable tags
- KMS key rotation enabled
- No wildcard IAM allow statements
- CloudTrail log validation enabled
- Required resource tags (`Project`, `Environment`, `Owner`, `ManagedBy`)

Test locally:
```bash
# Generate plan JSON
cd terraform && terraform plan -out=tfplan.binary && terraform show -json tfplan.binary > tfplan.json

# Run policy checks
conftest test tfplan.json --policy ../policies/ --namespace terraform.security
```
