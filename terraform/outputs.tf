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

output "security_alerts_topic_arn" {
  description = "SNS topic that receives security detection alarms"
  value       = aws_sns_topic.security_alerts.arn
}

output "cloudtrail_log_group_name" {
  description = "CloudWatch log group receiving CloudTrail events for detection"
  value       = aws_cloudwatch_log_group.cloudtrail.name
}

output "detection_alarm_names" {
  description = "CloudWatch alarms implementing the security detections"
  value = [
    aws_cloudwatch_metric_alarm.logging_disabled.alarm_name,
    aws_cloudwatch_metric_alarm.s3_public_access.alarm_name,
    aws_cloudwatch_metric_alarm.unexpected_oidc.alarm_name,
  ]
}
