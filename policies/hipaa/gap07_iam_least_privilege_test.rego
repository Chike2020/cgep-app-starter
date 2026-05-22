package compliance.hipaa.iam_least_privilege

import rego.v1

test_specific_actions_passes if {
    test_input := {
        "resource_changes": [{
            "type": "aws_iam_role_policy",
            "change": {
                "after": {
                    "name": "good-policy",
                    "policy": "{\"Statement\":[{\"Action\":[\"s3:GetObject\",\"dynamodb:PutItem\"]}]}"
                }
            }
        }]
    }
    
    result := deny with input as test_input
    count(result) == 0
}

test_wildcard_actions_fails if {
    test_input := {
        "resource_changes": [{
            "type": "aws_iam_role_policy",
            "change": {
                "after": {
                    "name": "bad-policy",
                    "policy": "{\"Statement\":[{\"Action\":[\"s3:*\",\"dynamodb:*\"]}]}"
                }
            }
        }]
    }
    
    result := deny with input as test_input
    count(result) == 1
}