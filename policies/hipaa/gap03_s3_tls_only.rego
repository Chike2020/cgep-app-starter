# METADATA
# title: HIPAA 164.312(e)(1) - S3 Transmission Security (TLS-Only)
# description: Ensures S3 buckets with PHI deny non-TLS requests
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(e)(1)"
#   severity: high
#   gap: GAP-03
package compliance.hipaa.s3_tls_only

import rego.v1

# Check if bucket has PHI
is_phi_bucket(resource) if {
    resource.type == "aws_s3_bucket"
    resource.change.after.tags.DataClass == "phi"
}

# Check if bucket has TLS-only policy
has_tls_policy(bucket_name) if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_policy"
    resource.change.after.bucket == bucket_name
    
    # Parse the policy JSON
    policy_str := resource.change.after.policy
    policy := json.unmarshal(policy_str)
    
    # Check for deny statement with SecureTransport condition
    some statement in policy.Statement
    statement.Effect == "Deny"
    statement.Condition.Bool["aws:SecureTransport"] == "false"
}

# Deny if PHI bucket lacks TLS-only policy
deny contains msg if {
    some resource in input.resource_changes
    is_phi_bucket(resource)
    bucket_name := resource.change.after.bucket
    not has_tls_policy(bucket_name)
    
    msg := sprintf(
        "HIPAA 164.312(e)(1) VIOLATION: S3 bucket '%s' contains PHI but does not enforce TLS-only access. Add bucket policy with Condition: aws:SecureTransport = false -> Deny",
        [bucket_name]
    )
}