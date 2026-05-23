######################################################################
# Evidence Vault - Immutable Audit Storage
# HIPAA 164.312(b) - Audit Controls
# HIPAA 164.308(a)(1)(ii)(D) - Information System Activity Review
######################################################################

resource "random_id" "vault_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "evidence_vault" {
  bucket = "${local.name_prefix}-evidence-vault-${random_id.vault_suffix.hex}"

  tags = {
    Name         = "${local.name_prefix}-evidence-vault"
    Purpose      = "audit-evidence"
    Compliance   = "hipaa"
    HIPAAControl = "164-312-b"
  }
}

# Object Lock configuration (COMPLIANCE mode - cannot be disabled)
resource "aws_s3_bucket_versioning" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 90
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence_vault]
}
# KMS encryption for evidence vault
resource "aws_s3_bucket_server_side_encryption_configuration" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# TLS-only policy
resource "aws_s3_bucket_policy" "evidence_vault_tls" {
  bucket = aws_s3_bucket.evidence_vault.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.evidence_vault.arn,
          "${aws_s3_bucket.evidence_vault.arn}/*"
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

output "evidence_vault_bucket" {
  value       = aws_s3_bucket.evidence_vault.id
  description = "S3 bucket for immutable audit evidence"
}

output "evidence_vault_arn" {
  value       = aws_s3_bucket.evidence_vault.arn
  description = "Evidence vault ARN"
}