######################################################################
# CloudTrail - Audit Logging
# HIPAA 164.312(b) - Audit Controls
# HIPAA 164.308(a)(1)(ii)(D) - Information System Activity Review
######################################################################

# S3 bucket for CloudTrail logs
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "${local.name_prefix}-cloudtrail-${local.suffix}"

  tags = {
    Name         = "${local.name_prefix}-cloudtrail"
    Purpose      = "audit-logs"
    Compliance   = "hipaa"
    HIPAAControl = "164-312-b"
  }
}

# Versioning for CloudTrail bucket
resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# KMS encryption for CloudTrail logs
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

# Block public access
resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CloudTrail bucket policy
resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail_logs.arn,
          "${aws_s3_bucket.cloudtrail_logs.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# Lifecycle: transition audit logs to cheaper tiers; expire after 7 years
# HIPAA 164.312(b) does not mandate a specific retention period, but 7 years
# is standard for healthcare audit logs.
resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    id     = "cloudtrail-log-tiering"
    status = "Enabled"

    filter {
      prefix = ""
    }

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 365
      storage_class = "GLACIER"
    }

    expiration {
      days = 2555 # 7 years
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# CloudTrail trail
resource "aws_cloudtrail" "main" {
  name                          = "${local.name_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.phi.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.uploads.arn}/*"]
    }

    data_resource {
      type   = "AWS::DynamoDB::Table"
      values = [aws_dynamodb_table.intake_compliant.arn]
    }
  }

  tags = {
    Name         = "${local.name_prefix}-trail"
    Compliance   = "hipaa"
    HIPAAControl = "164-312-b"
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]
}

output "cloudtrail_name" {
  value       = aws_cloudtrail.main.id
  description = "CloudTrail trail name"
}

output "cloudtrail_arn" {
  value       = aws_cloudtrail.main.arn
  description = "CloudTrail trail ARN"
}