# METADATA
# title: HIPAA 164.312(a)(2)(iv) - S3 Encryption with Customer-Managed Keys
# description: Ensures S3 buckets containing PHI use KMS CMK, not AWS-managed keys
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(2)(iv)"
#   severity: high
#   gap: GAP-01
package compliance.hipaa.s3_kms_encryption

import rego.v1

# Check if resource is an S3 bucket with PHI data class
is_phi_bucket(resource) if {
    resource.type == "aws_s3_bucket"
    resource.change.after.tags.DataClass == "phi"
}

# Check if bucket has KMS encryption configured
has_kms_encryption(bucket_name) if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    resource.change.after.bucket == bucket_name
    resource.change.after.rule[_].apply_server_side_encryption_by_default.sse_algorithm == "aws:kms"
}

# Deny if PHI bucket lacks KMS encryption
deny contains msg if {
    some resource in input.resource_changes
    is_phi_bucket(resource)
    bucket_name := resource.change.after.bucket
    not has_kms_encryption(bucket_name)
    
    msg := sprintf(
        "HIPAA 164.312(a)(2)(iv) VIOLATION: S3 bucket '%s' contains PHI but does not use KMS CMK encryption. PHI encryption keys must be under customer control. Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm='aws:kms'",
        [bucket_name]
    )
}