package compliance.hipaa.lambda_dlq_concurrency

import rego.v1

phi_lambda_compliant := {
	"resource_changes": [{
		"type": "aws_lambda_function",
		"change": {"after": {
			"function_name": "acme-health-intake-handler",
			"tags": {"DataClass": "phi"},
			"dead_letter_config": [{"target_arn": "arn:aws:sqs:us-east-1:123456789012:my-dlq"}],
			"reserved_concurrent_executions": 5,
		}},
	}],
}

phi_lambda_no_dlq := {
	"resource_changes": [{
		"type": "aws_lambda_function",
		"change": {"after": {
			"function_name": "acme-health-intake-handler",
			"tags": {"DataClass": "phi"},
			"dead_letter_config": null,
			"reserved_concurrent_executions": 5,
		}},
	}],
}

phi_lambda_no_concurrency := {
	"resource_changes": [{
		"type": "aws_lambda_function",
		"change": {"after": {
			"function_name": "acme-health-intake-handler",
			"tags": {"DataClass": "phi"},
			"dead_letter_config": [{"target_arn": "arn:aws:sqs:us-east-1:123456789012:my-dlq"}],
			"reserved_concurrent_executions": null,
		}},
	}],
}

non_phi_lambda := {
	"resource_changes": [{
		"type": "aws_lambda_function",
		"change": {"after": {
			"function_name": "public-utility-fn",
			"tags": {"DataClass": "public"},
			"dead_letter_config": null,
			"reserved_concurrent_executions": null,
		}},
	}],
}

test_phi_lambda_with_dlq_and_concurrency_passes if {
	result := deny with input as phi_lambda_compliant
	count(result) == 0
}

test_phi_lambda_without_dlq_fails if {
	result := deny with input as phi_lambda_no_dlq
	count(result) == 1
}

test_phi_lambda_without_concurrency_fails if {
	result := deny with input as phi_lambda_no_concurrency
	count(result) == 1
}

test_non_phi_lambda_ignored if {
	result := deny with input as non_phi_lambda
	count(result) == 0
}
