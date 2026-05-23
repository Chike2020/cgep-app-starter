# METADATA
# title: SOC 2 CC7.2 / CMMC SI.L2-3.14.6 - Lambda Resilience Controls
# description: Lambda functions handling PHI must have a DLQ and reserved concurrency
# custom:
#   framework: hipaa
#   controls:
#     - "SOC2 CC7.2"
#     - "CMMC SI.L2-3.14.6"
#   severity: medium
#   gap: GAP-06
package compliance.hipaa.lambda_dlq_concurrency

import rego.v1

is_phi_lambda(resource) if {
	resource.type == "aws_lambda_function"
	resource.change.after.tags.DataClass == "phi"
}

has_dlq(resource) if {
	dlq := resource.change.after.dead_letter_config
	dlq != null
	count(dlq) > 0
	dlq[_].target_arn != ""
}

has_reserved_concurrency(resource) if {
	rc := resource.change.after.reserved_concurrent_executions
	rc != null
	rc >= 0
}

deny contains msg if {
	some resource in input.resource_changes
	is_phi_lambda(resource)
	not has_dlq(resource)
	function_name := resource.change.after.function_name

	msg := sprintf(
		"SOC2 CC7.2 VIOLATION: Lambda function '%s' handles PHI but has no dead_letter_config. Add a DLQ (SQS or SNS) to capture failed invocations",
		[function_name],
	)
}

deny contains msg if {
	some resource in input.resource_changes
	is_phi_lambda(resource)
	not has_reserved_concurrency(resource)
	function_name := resource.change.after.function_name

	msg := sprintf(
		"SOC2 CC7.2 VIOLATION: Lambda function '%s' handles PHI but has no reserved_concurrent_executions set. Set a concurrency limit to prevent resource exhaustion",
		[function_name],
	)
}
