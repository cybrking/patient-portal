variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (production, staging, etc.)"
  type        = string
}

variable "db_username" {
  description = "RDS master username (non-sensitive identifier, not the password)"
  type        = string
  default     = "healthbridge"
}

# NOTE: db_password and redis_auth_token have been intentionally removed.
# Credentials are stored in and retrieved from AWS Secrets Manager.
# Seed the secrets out-of-band before the first `terraform apply`:
#
#   aws secretsmanager put-secret-value \
#     --secret-id healthbridge/<env>/db-password \
#     --secret-string '<password>'
#
#   aws secretsmanager put-secret-value \
#     --secret-id healthbridge/<env>/redis-auth-token \
#     --secret-string '<token>'

variable "acm_certificate_arn" {
  description = "ARN of the ACM certificate for the ALB HTTPS listener"
  type        = string
}

variable "cicd_role_arn" {
  description = "IAM Role ARN of the CI/CD pipeline that is allowed to access the Terraform state S3 bucket"
  type        = string
  # Example: "arn:aws:iam::123456789:role/healthbridge-cicd-role"
}
