package compliance.hipaa.iam_least_privilege

import rego.v1

test_specific_actions_passes if {
	test_input := {"resource_changes": [{
		"type": "aws_iam_role_policy",
		"change": {"after": {
			"name": "good-policy",
			"policy": "{\"Statement\":[{\"Action\":[\"s3:GetObject\",\"dynamodb:PutItem\"]}]}",
		}},
	}]}

	result := deny with input as test_input
	count(result) == 0
}

# Wildcard in array format: Action = ["s3:*", "dynamodb:*"]
test_wildcard_array_fails if {
	test_input := {"resource_changes": [{
		"type": "aws_iam_role_policy",
		"change": {"after": {
			"name": "bad-policy-array",
			"policy": "{\"Statement\":[{\"Action\":[\"s3:*\",\"dynamodb:*\"]}]}",
		}},
	}]}

	result := deny with input as test_input
	count(result) == 1
}

# Wildcard in string format: Action = "s3:*"  (used by the starter's lambda_inline)
test_wildcard_string_fails if {
	test_input := {"resource_changes": [{
		"type": "aws_iam_role_policy",
		"change": {"after": {
			"name": "bad-policy-string",
			"policy": "{\"Statement\":[{\"Action\":\"s3:*\"}]}",
		}},
	}]}

	result := deny with input as test_input
	count(result) == 1
}