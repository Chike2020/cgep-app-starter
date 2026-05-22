package compliance.hipaa.lambda_vpc

import rego.v1

test_phi_lambda_in_vpc_passes if {
    test_input := {
        "resource_changes": [{
            "type": "aws_lambda_function",
            "change": {
                "after": {
                    "function_name": "phi-lambda",
                    "tags": {"DataClass": "phi"},
                    "vpc_config": [{"subnet_ids": ["subnet-123"]}]
                }
            }
        }]
    }
    
    result := deny with input as test_input
    count(result) == 0
}

test_phi_lambda_without_vpc_fails if {
    test_input := {
        "resource_changes": [{
            "type": "aws_lambda_function",
            "change": {
                "after": {
                    "function_name": "bad-lambda",
                    "tags": {"DataClass": "phi"}
                }
            }
        }]
    }
    
    result := deny with input as test_input
    count(result) == 1
}