# Partial backend configuration for the dev environment.
# Usage: terraform init -backend-config=backend-dev.hcl
#
# These values are static because Terraform reads backend config before it
# evaluates variables — interpolation is not allowed inside a backend block.
#
# The bucket and lock table below must already exist before running init
# (the bootstrap problem: Terraform can't create the bucket that stores its
# own state). Create them once, manually or via a separate minimal config.

bucket         = "harshah08-tfstate-dev"
key            = "secure-pipeline/terraform.tfstate"
region         = "us-east-1"
encrypt        = true
dynamodb_table = "tf-state-lock"
