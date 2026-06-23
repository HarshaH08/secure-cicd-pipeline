output "ecr_repository_url" {
  description = "ECR repository URL for docker push commands"
  value       = aws_ecr_repository.app.repository_url
}

output "artifacts_bucket_name" {
  description = "S3 bucket for CI/CD artifacts"
  value       = aws_s3_bucket.artifacts.bucket
}

output "cicd_role_arn" {
  description = "ARN of the IAM role GitHub Actions assumes via OIDC"
  value       = aws_iam_role.cicd.arn
}

output "cloudtrail_name" {
  description = "CloudTrail trail name for audit logging"
  value       = aws_cloudtrail.pipeline.name
}
