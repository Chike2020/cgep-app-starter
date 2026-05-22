# METADATA
# title: HIPAA 164.312(a)(2)(iv) - DynamoDB Encryption with Customer-Managed Keys
# description: Ensures DynamoDB tables containing PHI use KMS CMK
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(2)(iv)"
#   severity: high
#   gap: GAP-02
package compliance.hipaa.dynamodb_kms

import rego.v1

# Check if resource is a DynamoDB table with PHI
is_phi_table(resource) if {
    resource.type == "aws_dynamodb_table"
    resource.change.after.tags.DataClass == "phi"
}

# Check if table has KMS encryption
has_kms_encryption(resource) if {
    resource.change.after.server_side_encryption[_].enabled == true
    resource.change.after.server_side_encryption[_].kms_key_arn != null
}

# Deny if PHI table lacks KMS encryption
deny contains msg if {
    some resource in input.resource_changes
    is_phi_table(resource)
    not has_kms_encryption(resource)
    table_name := resource.change.after.name
    
    msg := sprintf(
        "HIPAA 164.312(a)(2)(iv) VIOLATION: DynamoDB table '%s' contains PHI but does not use KMS CMK encryption. Add server_side_encryption block with kms_key_arn",
        [table_name]
    )
}