package compliance.hipaa.dynamodb_kms

import rego.v1

# Test: PASS - PHI table with KMS
test_phi_table_with_kms_passes if {
    test_input := {
        "resource_changes": [{
            "type": "aws_dynamodb_table",
            "change": {
                "after": {
                    "name": "phi-table",
                    "tags": {"DataClass": "phi"},
                    "server_side_encryption": [{
                        "enabled": true,
                        "kms_key_arn": "arn:aws:kms:us-east-1:123:key/abc"
                    }]
                }
            }
        }]
    }
    
    result := deny with input as test_input
    count(result) == 0
}

# Test: FAIL - PHI table without KMS
test_phi_table_without_kms_fails if {
    test_input := {
        "resource_changes": [{
            "type": "aws_dynamodb_table",
            "change": {
                "after": {
                    "name": "bad-table",
                    "tags": {"DataClass": "phi"}
                }
            }
        }]
    }
    
    result := deny with input as test_input
    count(result) == 1
    some msg in result
    contains(msg, "164.312(a)(2)(iv)")
    contains(msg, "bad-table")
}