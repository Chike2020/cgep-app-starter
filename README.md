# HIPAA Compliance Automation — Patient Intake API

[![HIPAA Compliance Gate](https://github.com/Chike2020/cgep-app-starter/actions/workflows/hipaa-compliance-gate.yml/badge.svg)](https://github.com/Chike2020/cgep-app-starter/actions/workflows/hipaa-compliance-gate.yml)

**CGE-P Capstone** · Gideon Okechukwu · May 2026  
**Primary framework:** HIPAA Security Rule (45 CFR Part 164)

---

## What this repo is

A GRC baseline wrapped around the `cgep-app-starter` Patient Intake API. It closes **all 8 intentional security gaps** with Terraform, enforces them with **8 Rego policies** via conftest, produces cryptographically signed evidence on every push to `main`, and detects runtime drift daily via AWS Config + EventBridge.

Full design rationale and trade-offs: [`WRITEUP.md`](WRITEUP.md)

**Bidirectional control-to-code traceability:** [`controls-mapping.csv`](controls-mapping.csv) — maps each gap ID → HIPAA control → Rego policy file → Terraform resource → Terraform file → CI check → OSCAL component.

**Monitoring & drift detection:** [`terraform/monitoring.tf`](terraform/monitoring.tf) — AWS Config rules (S3, DynamoDB, CloudTrail, KMS), EventBridge daily schedule, drift-detector Lambda (with DLQ + reserved concurrency), SNS compliance alerts.

---

## Grader verification

### 1  Deploy and smoke-test the workload

```bash
git clone https://github.com/Chike2020/cgep-app-starter
cd cgep-app-starter
make deploy AWS_PROFILE=<your-sandbox>
make test   AWS_PROFILE=<your-sandbox>
# Expected: {"submission_id": "...", "status": "received"}
```

### 2  Run policy tests locally

```bash
# OPA unit tests — 8 policies, 20 tests (requires opa in PATH)
opa test policies/hipaa/ -v
# Expected: PASS 20/20

# Terraform validation + native integration tests
cd terraform
terraform init
terraform fmt -check -recursive          # exit 0
terraform validate                        # Success!
terraform test -test-directory=tests/    # 11/11 passed
```

### 3  Verify the evidence vault

```bash
# List signed bundles (replace bucket name from terraform output)
VAULT=$(cd terraform && terraform output -raw evidence_vault_bucket)
aws s3 ls s3://$VAULT/runs/ --recursive

# Download a bundle and verify Cosign signature
BUNDLE=<bundle-name>.tar.gz
aws s3 cp s3://$VAULT/runs/<run-id>/$BUNDLE .
aws s3 cp s3://$VAULT/runs/<run-id>/$BUNDLE.sig.bundle .

cosign verify-blob \
  --bundle $BUNDLE.sig.bundle \
  --certificate-identity-regexp="https://github.com/Chike2020/cgep-app-starter" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  $BUNDLE
# Expected: Verified OK

# Verify SHA-256 integrity
aws s3 cp s3://$VAULT/runs/<run-id>/$BUNDLE.sha256 .
echo "$(cat $BUNDLE.sha256)  $BUNDLE" | sha256sum -c
# Expected: OK

# Confirm Object Lock retention (COMPLIANCE mode, 90 days)
aws s3api get-object-retention \
  --bucket $VAULT \
  --key runs/<run-id>/$BUNDLE
```

### 4  Verify the RED/GREEN PRs

| PR | Title | Result |
|----|-------|--------|
| [#1](https://github.com/Chike2020/cgep-app-starter/pull/1) | TEST RED: S3 bucket without KMS | Blocked (policy gate fired) |
| [#2](https://github.com/Chike2020/cgep-app-starter/pull/2) | TEST GREEN: Non-PHI bucket | Merged (all policies passed) |

### 5  Verify monitoring infrastructure (`terraform/monitoring.tf`)

```bash
# List all AWS Config rules deployed
aws configservice describe-config-rules \
  --query 'ConfigRules[*].ConfigRuleName' --output table

# Verify EventBridge daily drift-check rule
aws events describe-rule --name acme-health-intake-daily-drift-check

# Check drift-detector Lambda configuration
aws lambda get-function-configuration \
  --function-name $(cd terraform && terraform output -raw drift_detector_function_name) \
  --query '{Runtime:Runtime,ReservedConcurrency:reserved_concurrent_executions,DLQ:DeadLetterConfig}'

# Verify SNS compliance alerts topic
aws sns list-topics --query 'Topics[*].TopicArn' | grep compliance-alerts
```

Monitoring resources defined in [`terraform/monitoring.tf`](terraform/monitoring.tf):
- `aws_config_configuration_recorder.hipaa` — continuous Config recording
- `aws_config_config_rule.*` — 4 managed rules (S3 encryption, DynamoDB encryption, CloudTrail enabled, KMS rotation)
- `aws_cloudwatch_event_rule.daily_drift_check` — EventBridge cron (02:00 UTC daily)
- `aws_lambda_function.drift_detector` — queries Config, publishes NON_COMPLIANT findings to SNS
- `aws_sqs_queue.drift_detector_dlq` — KMS-encrypted DLQ (GAP-06 remediation)
- `aws_sns_topic.compliance_alerts` — fanout for real-time drift notifications

### 6  Validate OSCAL with trestle

```bash
pip install compliance-trestle
mkdir /tmp/trestle-check && cd /tmp/trestle-check
trestle init
trestle import -f /path/to/repo/oscal/component-definition.json -o patient-intake-api
trestle validate -t component-definition -n patient-intake-api
# Expected: VALID: Model passed all registered validation tests
```

### 7  Inspect the bidirectional control mapping

```bash
# View the full gap → control → policy → resource → CI traceability table
column -t -s, controls-mapping.csv | less -S
```

[`controls-mapping.csv`](controls-mapping.csv) provides the bidirectional mapping:
- **Forward:** Gap ID → HIPAA control → Rego policy → Terraform resource → CI check
- **Backward:** OSCAL component → Terraform resource → Rego policy → Gap ID

All 8 gaps (GAP-01 through GAP-08) plus 5 supporting controls are tracked.

---

## Control mapping

See [`controls-mapping.csv`](controls-mapping.csv) for the bidirectional gap → Rego policy → Terraform resource → OSCAL mapping.

| Gap | HIPAA Control | Status |
|-----|--------------|--------|
| GAP-01 | 164.312(a)(2)(iv) S3 CMK encryption | CLOSED |
| GAP-02 | 164.312(a)(2)(iv) DynamoDB CMK encryption | CLOSED |
| GAP-03 | 164.312(e)(1) TLS-only S3 access | CLOSED |
| GAP-04 | 164.308(a)(7) S3 versioning | CLOSED |
| GAP-05 | 164.312(e)(1) Lambda VPC isolation | CLOSED |
| GAP-06 | SOC2 CC7.2 Lambda DLQ + concurrency | CLOSED |
| GAP-07 | 164.312(a)(1) IAM least privilege | CLOSED |
| GAP-08 | 164.312(b) API Gateway logging + throttling | CLOSED |

---

## Repo layout

```
terraform/                   # IaC — KMS, S3 Object Lock vault, CloudTrail, compliance baseline
  main.tf                    # API Gateway (GAP-08), Lambda, VPC, DynamoDB, S3 (with intentional gaps)
  compliance-baseline.tf     # Remediations: GAP-01…GAP-08 Terraform resources
  monitoring.tf              # AWS Config rules, EventBridge, drift-detector Lambda, SNS alerts
  cloudtrail.tf              # Multi-region CloudTrail with KMS encryption
  evidence-vault.tf          # S3 Object Lock COMPLIANCE vault (90-day retention)
  kms.tf                     # KMS CMK with auto-rotation
  tests/                     # Terraform native integration tests (11/11 pass with mock_provider)
    hipaa_controls.tftest.hcl
policies/hipaa/              # 8 Rego policies + unit tests (20/20 OPA tests pass)
  gap01_s3_kms_encryption.rego          # GAP-01: S3 CMK
  gap02_dynamodb_kms.rego               # GAP-02: DynamoDB CMK
  gap03_s3_tls_only.rego                # GAP-03: TLS-only bucket policy
  gap04_s3_versioning.rego              # GAP-04: S3 versioning
  gap05_lambda_vpc.rego                 # GAP-05: Lambda VPC
  gap06_lambda_dlq_concurrency.rego     # GAP-06: DLQ + concurrency
  gap07_iam_least_privilege.rego        # GAP-07: IAM least privilege
  gap08_api_gw_logging.rego             # GAP-08: API Gateway logging + throttling
oscal/                       # OSCAL component-definition.json (trestle-validated, 8 controls)
controls-mapping.csv         # Bidirectional control→code traceability index (gap↔policy↔resource↔OSCAL)
.github/workflows/           # hipaa-compliance-gate.yml: Plan → conftest → Apply → Cosign → Upload
WRITEUP.md                   # Design rationale, trade-offs, and lessons learned
LICENSE                      # MIT License
```
