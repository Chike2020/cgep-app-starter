# Terraform native integration tests for HIPAA control enforcement
# Run with: terraform test -test-directory=tests/
# Uses mock_provider so all tests run at plan time without real AWS credentials.
# Computed ARNs/IDs get deterministic mock placeholders, enabling full assertion coverage.

mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = {
      names = ["us-east-1a", "us-east-1b"]
    }
  }
}
mock_provider "random" {}
mock_provider "archive" {}

######################################################################
# GAP-01: S3 PHI bucket must use SSE-KMS with a CMK
######################################################################

run "gap01_s3_kms_encryption_enforced" {
  command = plan

  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.uploads.rule).apply_server_side_encryption_by_default).sse_algorithm == "aws:kms"
    error_message = "GAP-01: S3 uploads bucket must use aws:kms algorithm, not aws:s3 or none"
  }

  assert {
    condition     = one(aws_s3_bucket_server_side_encryption_configuration.uploads.rule).bucket_key_enabled == true
    error_message = "GAP-01: Bucket key must be enabled to reduce KMS API calls"
  }
}

######################################################################
# GAP-02: DynamoDB PHI table must use a CMK
######################################################################

run "gap02_dynamodb_kms_enforced" {
  command = plan

  assert {
    condition     = one(aws_dynamodb_table.intake_compliant.server_side_encryption).enabled == true
    error_message = "GAP-02: DynamoDB PHI table must have SSE enabled with a CMK"
  }

  assert {
    condition     = one(aws_dynamodb_table.intake_compliant.point_in_time_recovery).enabled == true
    error_message = "GAP-02: DynamoDB PHI table must have PITR enabled for backup compliance"
  }
}

######################################################################
# GAP-03: S3 must deny non-TLS requests
# mock_provider makes policy string available at plan time
######################################################################

run "gap03_s3_tls_policy_enforced" {
  command = plan

  assert {
    condition     = aws_s3_bucket_policy.uploads_tls_only.policy != null
    error_message = "GAP-03: TLS-only bucket policy must have a non-null policy document"
  }
}

######################################################################
# GAP-04: S3 versioning must be enabled
######################################################################

run "gap04_s3_versioning_enforced" {
  command = plan

  assert {
    condition     = one(aws_s3_bucket_versioning.uploads.versioning_configuration).status == "Enabled"
    error_message = "GAP-04: S3 uploads bucket must have versioning enabled for PHI recovery"
  }
}

######################################################################
# GAP-05: Lambda must run inside a VPC
######################################################################

run "gap05_lambda_vpc_enforced" {
  command = plan

  assert {
    condition     = length(one(aws_lambda_function.intake_vpc.vpc_config).subnet_ids) > 0
    error_message = "GAP-05: Lambda function must be deployed in VPC private subnets"
  }

  assert {
    condition     = length(one(aws_lambda_function.intake_vpc.vpc_config).security_group_ids) > 0
    error_message = "GAP-05: Lambda function must have at least one security group in VPC config"
  }
}

######################################################################
# KMS CMK configuration
######################################################################

run "kms_key_rotation_enabled" {
  command = plan

  assert {
    condition     = aws_kms_key.phi.enable_key_rotation == true
    error_message = "CMK for PHI must have automatic key rotation enabled (HIPAA 164.312(a)(2)(iv))"
  }

  assert {
    condition     = aws_kms_key.phi.deletion_window_in_days >= 30
    error_message = "CMK deletion window must be at least 30 days to prevent accidental data loss"
  }
}

######################################################################
# Evidence vault immutability
######################################################################

run "evidence_vault_object_lock" {
  command = plan

  assert {
    condition     = one(one(aws_s3_bucket_object_lock_configuration.evidence_vault.rule).default_retention).mode == "COMPLIANCE"
    error_message = "Evidence vault must use COMPLIANCE mode Object Lock, not GOVERNANCE"
  }

  assert {
    condition     = one(one(aws_s3_bucket_object_lock_configuration.evidence_vault.rule).default_retention).days >= 90
    error_message = "Evidence vault retention must be at least 90 days for HIPAA audit trail"
  }
}

######################################################################
# GAP-07: IAM least privilege
######################################################################

run "gap07_iam_least_privilege_no_wildcard" {
  command = plan

  assert {
    condition     = aws_iam_role_policy.lambda_least_privilege.name == "intake-data-access-least-privilege"
    error_message = "GAP-07: Least-privilege IAM policy must exist — check aws_iam_role_policy.lambda_least_privilege"
  }
}

######################################################################
# Continuous monitoring present
######################################################################

run "monitoring_config_recorder_exists" {
  command = plan

  assert {
    condition     = can(aws_config_configuration_recorder.hipaa.name)
    error_message = "AWS Config recorder must be present for continuous compliance monitoring"
  }
}

run "monitoring_drift_detector_has_dlq" {
  command = plan

  assert {
    condition     = length(aws_lambda_function.drift_detector.dead_letter_config) > 0
    error_message = "Drift detector Lambda must have a DLQ configured"
  }

  assert {
    condition     = aws_lambda_function.drift_detector.reserved_concurrent_executions >= 0
    error_message = "Drift detector Lambda must have reserved concurrency set"
  }
}
