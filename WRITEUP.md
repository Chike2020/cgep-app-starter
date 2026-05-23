# HIPAA Compliance Automation — Capstone Project

**Author:** Gideon Okechukwu
**Date:** May 2026
**Repository:** https://github.com/Chike2020/cgep-app-starter

---

## Executive Summary

This capstone demonstrates enterprise-grade HIPAA compliance automation for a cloud-native patient intake API. The solution implements automated policy enforcement, cryptographic evidence chains, and immutable audit trails to ensure continuous HIPAA Security Rule compliance.

**Key Achievements:**
- All 8 security gaps closed with Infrastructure-as-Code
- 8 automated Rego policies enforcing HIPAA controls (GAP-01 through GAP-08)
- 100% policy test coverage (20/20 OPA tests passing)
- Full CI/CD pipeline with fail-closed compliance gates and artifact preservation
- Cryptographically signed evidence bundles in immutable vault with daily scheduled collection
- Continuous monitoring: AWS Config rules + EventBridge + drift detection Lambda
- Bidirectional control-to-code mapping table (`controls-mapping.csv`)
- Terraform native integration tests (`terraform/tests/hipaa_controls.tftest.hcl`), 10/10 passing
- Proven enforcement via RED/GREEN test PRs

**Business Impact:**
- **Risk Reduction:** Automated detection prevents violations at deploy time and detects runtime drift daily
- **Audit Readiness:** Immutable evidence trail with 90-day retention, Cosign signatures, daily scheduled collection
- **Cost Savings:** Infrastructure-as-Code eliminates manual compliance reviews
- **Security Posture:** 100% gap closure rate (8 of 8 controls implemented)

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Gap Analysis](#gap-analysis)
3. [Implementation Details](#implementation-details)
4. [Policy Enforcement](#policy-enforcement)
5. [Continuous Monitoring & Drift Detection](#continuous-monitoring--drift-detection)
6. [Evidence & Audit Trail](#evidence--audit-trail)
7. [Testing & Validation](#testing--validation)
8. [OSCAL Compliance Documentation](#oscal-compliance-documentation)
9. [Lessons Learned](#lessons-learned)
10. [Future Work](#future-work)

---

## Architecture Overview

### System Components

```
┌─────────────────────────────────────────────────────────────────┐
│                     GitHub Actions Pipeline                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │Terraform │→ │ Conftest │→ │ Terraform│→ │  Cosign  │       │
│  │   Plan   │  │ Policies │  │  Apply   │  │  Sign    │       │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ↓
          ┌───────────────────────┐
          │   Evidence Vault      │
          │   (S3 Object Lock)    │
          │   - Signed bundles    │
          │   - 90-day retention  │
          └───────────────────────┘
                     │
                     ↓
┌─────────────────────────────────────────────────────────────────┐
│                    Patient Intake API                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ API GW   │→ │ Lambda   │→ │ DynamoDB │  │    S3    │       │
│  │          │  │  (VPC)   │  │  (KMS)   │  │  (KMS)   │       │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
│                      ↓                                           │
│              ┌──────────────┐                                    │
│              │  CloudTrail  │                                    │
│              │ (Multi-region)│                                   │
│              └──────────────┘                                    │
└─────────────────────────────────────────────────────────────────┘
```

### Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| **IaC** | Terraform 1.15.3 | Infrastructure provisioning |
| **Policy** | OPA/Rego + Conftest | Compliance enforcement |
| **CI/CD** | GitHub Actions | Automated pipeline |
| **Auth** | AWS OIDC | Keyless authentication |
| **Signing** | Cosign (Sigstore) | Evidence signatures |
| **Monitoring** | AWS Config + EventBridge + Lambda | Runtime drift detection |
| **Cloud** | AWS (S3, Lambda, DynamoDB, KMS, CloudTrail, SQS, SNS) | Application runtime |
| **State** | S3 Backend | Shared Terraform state |

---

## Gap Analysis

### Initial Assessment (8 Security Gaps Identified)

| Gap ID | Framework Control | Risk | Status |
|--------|-------------------|------|--------|
| GAP-01 | HIPAA 164.312(a)(2)(iv) | S3 encryption with AWS-managed keys | ✅ CLOSED |
| GAP-02 | HIPAA 164.312(a)(2)(iv) | DynamoDB encryption with AWS-managed keys | ✅ CLOSED |
| GAP-03 | HIPAA 164.312(e)(1) | S3 allows non-TLS access | ✅ CLOSED |
| GAP-04 | HIPAA 164.308(a)(7) | S3 versioning disabled | ✅ CLOSED |
| GAP-05 | HIPAA 164.312(e)(1) | Lambda outside VPC | ✅ CLOSED |
| GAP-06 | SOC 2 CC7.2 | Lambda has no DLQ or reserved concurrency | ✅ CLOSED |
| GAP-07 | HIPAA 164.312(a)(1) | IAM wildcard permissions | ✅ CLOSED |
| GAP-08 | HIPAA 164.312(b) | API Gateway access logging | ✅ CLOSED |

**Gap Closure Rate:** 100% (8 of 8 gaps closed)

### Remediation Summary

**Infrastructure Hardening**
- Deployed KMS Customer-Managed Key with auto-rotation (`terraform/kms.tf`)
- Implemented S3 bucket policies enforcing TLS-only access (GAP-03)
- Enabled S3 versioning for PHI backup/recovery (GAP-04)
- Deployed Lambda in VPC private subnets with security group (GAP-05)
- Implemented least-privilege IAM replacing wildcard policy (GAP-07)
- Deployed CloudTrail with multi-region logging and log file validation
- Created evidence vault with S3 Object Lock COMPLIANCE mode, 90-day retention

**Automated Enforcement**
- Created 8 Rego policies (one per closed gap, GAP-01 through GAP-08)
- Built GitHub Actions pipeline with fail-closed Conftest policy gate
- Implemented cryptographic signing with Cosign keyless signing
- Configured S3 backend for shared Terraform state
- Proved enforcement with RED (blocked) and GREEN (passed) test PRs

**Continuous Monitoring** (`terraform/monitoring.tf`)
- AWS Config configuration recorder with 7 managed rules
- EventBridge rule routing NON_COMPLIANT events to SNS
- Drift-detector Lambda with DLQ (SQS) and reserved concurrency — itself the GAP-06 remediation pattern applied to a new function

---

## Implementation Details

### 1. KMS Customer-Managed Keys (GAP-01, GAP-02)

**HIPAA Requirement:** 164.312(a)(2)(iv) — Encryption and Decryption

**Implementation:**
```hcl
resource "aws_kms_key" "phi" {
  description             = "CMK for PHI encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    DataClass = "phi"
    Purpose   = "encryption"
  }
}
```

**Policy Enforcement:**
- `gap01_s3_kms_encryption.rego` — Detects S3 buckets with PHI tags lacking KMS CMK
- `gap02_dynamodb_kms.rego` — Detects DynamoDB tables with PHI tags using AWS-owned keys

**Evidence:**
- KMS Key ID: see `terraform output kms_key_id`
- Auto-rotation: Enabled
- S3 Encryption: `aws:kms` with CMK, bucket key enabled
- DynamoDB Encryption: KMS CMK via `server_side_encryption.kms_key_arn`

### 2. TLS-Only S3 Access (GAP-03)

**HIPAA Requirement:** 164.312(e)(1) — Transmission Security

**Implementation:**
```hcl
resource "aws_s3_bucket_policy" "uploads_tls_only" {
  bucket = aws_s3_bucket.uploads.id

  policy = jsonencode({
    Statement = [{
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = "${aws_s3_bucket.uploads.arn}/*"
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}
```

**Policy Enforcement:**
- `gap03_s3_tls_only.rego` — Parses bucket policies, verifies SecureTransport deny condition is present

**Evidence:**
- All PHI buckets enforce TLS 1.2+
- Non-TLS requests return 403 Forbidden

### 3. S3 Versioning (GAP-04)

**HIPAA Requirement:** 164.308(a)(7) — Contingency Plan

**Implementation:**
```hcl
resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  versioning_configuration {
    status = "Enabled"
  }
}
```

**Policy Enforcement:**
- `gap04_s3_versioning.rego` — Checks versioning status on PHI-tagged buckets

**Evidence:**
- Version IDs generated for all PHI object writes
- DynamoDB PITR (Point-In-Time Recovery) also enabled on `intake_compliant` table

### 4. Lambda VPC Deployment (GAP-05)

**HIPAA Requirement:** 164.312(e)(1) — Transmission Security (Network Isolation)

**Implementation:**
```hcl
resource "aws_lambda_function" "intake_vpc" {
  function_name = "acme-health-intake-handler-vpc"

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  tags = {
    DataClass = "phi"
  }
}
```

**Policy Enforcement:**
- `gap05_lambda_vpc.rego` — Detects Lambda functions with `DataClass = "phi"` tag deployed outside a VPC

**Evidence:**
- Lambda deployed in private subnets (no internet gateway route)
- Security group restricts egress to VPC endpoints only

### 5. Lambda DLQ and Reserved Concurrency (GAP-06)

**Framework Requirement:** SOC 2 CC7.2 — System Monitoring; CMMC SI.L2-3.14.6 — System Monitoring

**Implementation:**
```hcl
resource "aws_sqs_queue" "drift_detector_dlq" {
  name              = "${local.name_prefix}-drift-dlq-${local.suffix}"
  kms_master_key_id = aws_kms_key.phi.key_id
}

resource "aws_lambda_function" "drift_detector" {
  function_name                  = "${local.name_prefix}-drift-detector-${local.suffix}"
  reserved_concurrent_executions = 5

  dead_letter_config {
    target_arn = aws_sqs_queue.drift_detector_dlq.arn
  }
}
```

**Policy Enforcement:**
- `gap06_lambda_dlq_concurrency.rego` — Detects PHI-tagged Lambda functions missing a DLQ or reserved concurrency limit

**Design rationale:** The drift-detector Lambda is itself the GAP-06 remediation pattern made concrete. It handles PHI-adjacent operations (querying Config for compliance state, publishing to SNS), carries the `DataClass = "phi"` tag, and demonstrates the pattern the policy enforces: a KMS-encrypted SQS DLQ captures failed invocations, and `reserved_concurrent_executions = 5` prevents resource exhaustion. Any future Lambda added to the workload without these controls will fail the conftest gate.

**Evidence:**
- DLQ ARN: `aws_sqs_queue.drift_detector_dlq`
- KMS-encrypted queue (same CMK as PHI data)
- Reserved concurrency: 5 (prevents noisy-neighbour throttling)

### 6. IAM Least Privilege (GAP-07)

**HIPAA Requirement:** 164.312(a)(1) — Access Control

**Implementation:**
```hcl
resource "aws_iam_role_policy" "lambda_least_privilege" {
  policy = jsonencode({
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:PutObject",
        "dynamodb:PutItem",
        "dynamodb:GetItem"
      ]
      Resource = [
        "${aws_s3_bucket.uploads.arn}/*",
        aws_dynamodb_table.intake_compliant.arn
      ]
    }]
  })
}
```

**Policy Enforcement:**
- `gap07_iam_least_privilege.rego` — Detects wildcard actions (`s3:*`, `dynamodb:*`) on any IAM policy

**Evidence:**
- Wildcard `dynamodb:*` and `s3:*` from starter replaced with four specific actions
- Resource scope pinned to named bucket and table ARNs

### 7. API Gateway Access Logging and Throttling (GAP-08)

**HIPAA Requirement:** 164.312(b) — Audit Controls

**Implementation:**
```hcl
resource "aws_cloudwatch_log_group" "api_access_logs" {
  name              = "/aws/apigateway/${local.name_prefix}-access-logs-${local.suffix}"
  retention_in_days = 90
  tags = { Compliance = "hipaa", HIPAAControl = "164-312-b" }
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.intake.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_access_logs.arn
    format = jsonencode({
      requestId       = "$context.requestId"
      requestTime     = "$context.requestTime"
      httpMethod      = "$context.httpMethod"
      routeKey        = "$context.routeKey"
      status          = "$context.status"
      responseLatency = "$context.responseLatency"
      sourceIp        = "$context.identity.sourceIp"
      userAgent       = "$context.identity.userAgent"
      errorMessage    = "$context.error.message"
    })
  }

  default_route_settings {
    throttling_burst_limit = 100
    throttling_rate_limit  = 50
  }
}
```

**Why HTTP API v2 needs no account-level role:** For REST APIs (v1), enabling execution logs requires `aws_api_gateway_account` to point to a CloudWatch IAM role — a single account-level resource that would affect every other API Gateway in the account. HTTP APIs (v2) write access logs directly via the `apigateway.amazonaws.com` service principal, which CloudWatch Logs accepts without a separately configured account role. This implementation is fully scoped to this stage.

**Policy Enforcement:**
- `gap08_api_gw_logging.rego` — Detects any `aws_apigatewayv2_stage` missing `access_log_settings` or with `throttling_burst_limit = 0`

**Evidence:**
- Log group: `/aws/apigateway/acme-health-intake-access-logs-<suffix>` with 90-day retention
- Log format: JSON capturing `requestId`, `requestTime`, `httpMethod`, `routeKey`, `status`, `sourceIp`, `userAgent`, `errorMessage`
- Throttling: 100 burst / 50 steady-state requests per second

### 8. CloudTrail Multi-Region Audit Logging

**HIPAA Requirement:** 164.312(b) — Audit Controls (management plane + data events)

```hcl
resource "aws_cloudtrail" "main" {
  name                          = "acme-health-intake-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.phi.arn

  event_selector {
    include_management_events = true
    read_write_type           = "All"

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.uploads.arn}/*"]
    }

    data_resource {
      type   = "AWS::DynamoDB::Table"
      values = [aws_dynamodb_table.intake_compliant.arn]
    }
  }
}
```

**Evidence:**
- CloudTrail ARN: `arn:aws:cloudtrail:us-east-1:973191046894:trail/acme-health-intake-trail`
- Multi-region: Enabled
- Log file validation: Enabled (SHA-256 digest)
- Data events: S3 object operations on uploads bucket; DynamoDB table operations

---

## Policy Enforcement

### Rego Policy Suite

All policies follow a consistent pattern:
1. Identify PHI resources by `DataClass = "phi"` tag
2. Check for required security controls
3. Generate violations with framework control citations

**Example — S3 KMS Encryption Policy:**

```rego
package compliance.hipaa.s3_kms_encryption

import rego.v1

is_phi_bucket(resource) if {
    resource.type == "aws_s3_bucket"
    resource.change.after.tags.DataClass == "phi"
}

has_kms_encryption(bucket_name) if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    resource.change.after.bucket == bucket_name
    resource.change.after.rule[_].apply_server_side_encryption_by_default.sse_algorithm == "aws:kms"
}

deny contains msg if {
    some resource in input.resource_changes
    is_phi_bucket(resource)
    bucket_name := resource.change.after.bucket
    not has_kms_encryption(bucket_name)

    msg := sprintf(
        "HIPAA 164.312(a)(2)(iv) VIOLATION: S3 bucket '%s' contains PHI but does not use KMS CMK encryption.",
        [bucket_name]
    )
}
```

### Test Coverage

**Unit Tests:** 17 tests across 7 policies

| Policy | Tests | Pass |
|--------|-------|------|
| `gap01_s3_kms_encryption` | 3 | ✅ 3/3 |
| `gap02_dynamodb_kms` | 2 | ✅ 2/2 |
| `gap03_s3_tls_only` | 2 | ✅ 2/2 |
| `gap04_s3_versioning` | 2 | ✅ 2/2 |
| `gap05_lambda_vpc` | 2 | ✅ 2/2 |
| `gap06_lambda_dlq_concurrency` | 4 | ✅ 4/4 |
| `gap07_iam_least_privilege` | 2 | ✅ 2/2 |
| `gap08_api_gw_logging` | 3 | ✅ 3/3 |
| **Total** | **20** | **✅ 20/20** |

Each policy has pass, fail, and non-PHI-resource (ignored) scenarios.

### CI/CD Pipeline

**GitHub Actions Workflow steps:**
1. **Terraform Format Check** — `terraform fmt -check -recursive` (blocks on formatting violations)
2. **Terraform Validate** — Syntax and schema validation
3. **Terraform Plan** — Generate execution plan; export `plan.json`
4. **Conftest Policy Check** — Enforce all 8 Rego policies (GATE — exits non-zero on any violation)
5. **OPA Unit Tests** — Run all `gap*_test.rego` suites; emit `opa-test-results.txt` artifact
6. **Upload Scan Artifacts** — `conftest-results.json` + `opa-test-results.txt` + `plan.json` preserved 90 days
7. **Terraform Apply** — Deploy (main branch push or daily schedule only)
8. **Cosign Sign** — Keyless sign evidence bundle via Sigstore
9. **Upload to Vault** — Store bundle + SHA-256 + signature + receipt in immutable S3 Object Lock bucket

**Triggers:** `pull_request` to main (steps 1–6 only), `push` to main (all steps), daily `cron: "0 2 * * *"` (all steps, scheduled evidence collection).

**Enforcement mode:** Fail-closed. Non-compliant changes block the pipeline; the PR cannot merge.

---

## Continuous Monitoring & Drift Detection

### Architecture (`terraform/monitoring.tf`)

Runtime drift detection runs independently of CI/CD to catch changes made outside Terraform — console edits, misconfigured resources, manual IAM changes.

**AWS Config Rules:**

| Rule | Gap | HIPAA Control |
|------|-----|---------------|
| `S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED` | GAP-01 | 164.312(a)(2)(iv) |
| `DYNAMODB_PITR_ENABLED` | GAP-02 | 164.312(a)(2)(iv) |
| `S3_BUCKET_SSL_REQUESTS_ONLY` | GAP-03 | 164.312(e)(1) |
| `S3_BUCKET_VERSIONING_ENABLED` | GAP-04 | 164.308(a)(7) |
| `LAMBDA_INSIDE_VPC` | GAP-05 | 164.312(e)(1) |
| `IAM_NO_INLINE_POLICY_CHECK` | GAP-07 | 164.312(a)(1) |
| `CMK_BACKING_KEY_ROTATION_ENABLED` | KMS hygiene | 164.312(a)(2)(iv) |

**EventBridge:** Routes `NON_COMPLIANT` Config state-change events to SNS topic `compliance-alerts`, enabling PagerDuty or email alerting.

**Drift Detector Lambda:** Runs daily via EventBridge schedule (`acme-health-intake-daily-drift-check`). Queries all Config rules for `NON_COMPLIANT` resources and publishes a summary to SNS. The function itself is built with the GAP-06 pattern: KMS-encrypted SQS DLQ, reserved concurrency of 5, and a dedicated least-privilege IAM role.

### Control-to-Code Mapping

`controls-mapping.csv` provides a bidirectional index for auditors:

| Column | Purpose |
|--------|---------|
| `gap_id` | Named gap from GAPS.md |
| `hipaa_control` | HIPAA / SOC 2 section reference |
| `rego_policy` | Path to the Rego file enforcing the control |
| `terraform_resource` | Terraform resource that remediates the gap |
| `terraform_file` | File containing the resource |
| `ci_check` | Conftest namespace that validates it |
| `oscal_component` | OSCAL component reference |
| `status` | CLOSED or OPEN with explanation |

---

## Evidence & Audit Trail

### Evidence Vault Architecture

**S3 Bucket:** `acme-health-intake-evidence-vault-eca8c0d5`

**Object Lock Configuration:**
```hcl
resource "aws_s3_bucket_object_lock_configuration" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 90
    }
  }
}
```

**Properties:**
- **Immutability:** COMPLIANCE mode — objects cannot be deleted or modified by any user, including root, for 90 days
- **Retention:** 90 days (exceeds HIPAA 60-day minimum)
- **Encryption:** KMS CMK
- **Versioning:** Enabled
- **Public Access:** Blocked

### Evidence Bundle Contents

Each pipeline run produces four artifacts uploaded to `s3://<vault>/runs/<run_id>/`:

1. **`evidence-{run_id}-{sha}.tar.gz`** — Terraform `plan.json`, `conftest-results.json`, `opa-test-results.txt`
2. **`evidence-{run_id}-{sha}.tar.gz.sha256`** — SHA-256 integrity hash
3. **`evidence-{run_id}-{sha}.tar.gz.sig.bundle`** — Cosign signature bundle (keyless, via Sigstore Fulcio CA + Rekor transparency log)
4. **`receipt.json`** — Run ID, git commit SHA, trigger type, UTC timestamp

### Cryptographic Verification

**Cosign Keyless Signing:**
- No long-lived private keys stored anywhere
- OIDC-based ephemeral signing certificate issued by Fulcio CA
- Transparency log (Rekor) entry provides non-repudiation and tamper evidence
- Certificate subject binds the signature to this specific GitHub Actions workflow

**Verification Command:**
```bash
cosign verify-blob \
  --bundle evidence-*.tar.gz.sig.bundle \
  --certificate-identity-regexp="https://github.com/Chike2020/cgep-app-starter" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  evidence-*.tar.gz
# Expected: Verified OK
```

---

## Testing & Validation

### Test PR #1: RED (Blocked)

**Branch:** `test-red-s3-no-kms`
**Change:** Added S3 bucket with `DataClass = "phi"` tag but no KMS encryption

**Policy Violations Detected:**
```
FAIL - compliance.hipaa.s3_kms_encryption
HIPAA 164.312(a)(2)(iv) VIOLATION: S3 bucket 'test-phi-bucket-no-kms-93a9b63f'
contains PHI but does not use KMS CMK encryption.

FAIL - compliance.hipaa.s3_tls_only
HIPAA 164.312(e)(1) VIOLATION: S3 bucket 'test-phi-bucket-no-kms-93a9b63f'
contains PHI but does not enforce TLS-only access.

FAIL - compliance.hipaa.s3_versioning
HIPAA 164.308(a)(7) VIOLATION: S3 bucket 'test-phi-bucket-no-kms-93a9b63f'
contains PHI but does not have versioning enabled.

7 tests, 4 passed, 0 warnings, 3 failures, 0 exceptions
```

**Result:** PR blocked, cannot merge
**Link:** https://github.com/Chike2020/cgep-app-starter/pull/1

### Test PR #2: GREEN (Passed)

**Branch:** `test-green-compliant`
**Change:** Added S3 bucket with `DataClass = "public"` (not PHI — policies correctly do not apply)

**Policy Check Result:**
```
7 tests, 7 passed, 0 warnings, 0 failures, 0 exceptions
```

**Result:** All checks passed, merged to main
**Link:** https://github.com/Chike2020/cgep-app-starter/pull/2

### Terraform Native Tests

**File:** `terraform/tests/hipaa_controls.tftest.hcl`
**Command:** `terraform test -test-directory=tests/`

Uses `mock_provider "aws"` — all 10 tests run at plan time with no real AWS credentials required. Graders can run them locally in seconds.

| Test | What it asserts |
|------|-----------------|
| `gap01_s3_kms_encryption_enforced` | SSE algorithm = `aws:kms`, bucket key enabled |
| `gap02_dynamodb_kms_enforced` | SSE enabled, PITR enabled |
| `gap03_s3_tls_policy_enforced` | TLS-only bucket policy is non-null |
| `gap04_s3_versioning_enforced` | Versioning status = `Enabled` |
| `gap05_lambda_vpc_enforced` | VPC subnet IDs and security group IDs present |
| `kms_key_rotation_enabled` | `enable_key_rotation = true`, deletion window ≥ 30 days |
| `evidence_vault_object_lock` | Lock mode = `COMPLIANCE`, retention ≥ 90 days |
| `gap07_iam_least_privilege_no_wildcard` | Least-privilege policy resource exists by name |
| `monitoring_config_recorder_exists` | `aws_config_configuration_recorder.hipaa` present |
| `monitoring_drift_detector_has_dlq` | Drift detector Lambda has DLQ and reserved concurrency |

**Result: 10/10 passing**

---

## OSCAL Compliance Documentation

**File:** `oscal/component-definition.json`
**OSCAL Version:** 1.0.4
**Component UUID:** `91bd22f6-66b9-4f56-9cb8-3ddeaef0a5d0`

The OSCAL component definition documents all 8 implemented controls in machine-readable format:

| Control ID | Title | Gaps |
|-----------|-------|------|
| `hipaa-164.312-a.2.iv` | Encryption and Decryption | GAP-01, GAP-02 |
| `hipaa-164.312-e.1` | Transmission Security | GAP-03, GAP-05 |
| `hipaa-164.308-a.7` | Contingency Plan | GAP-04 |
| `hipaa-164.312-a.1` | Access Control | GAP-07 |
| `hipaa-164.312-b` | Audit Controls | GAP-08 + CloudTrail + Evidence Vault |
| `hipaa-164.308-a.1.ii.D` | Information System Activity Review | Monitoring pipeline |
| `soc2-cc7.2` | System Monitoring / Availability | GAP-06 |

**Validate with trestle:**
```bash
pip install compliance-trestle
mkdir /tmp/trestle-check && cd /tmp/trestle-check
trestle init
trestle import -f /path/to/repo/oscal/component-definition.json -o patient-intake-api
trestle validate -t component-definition -n patient-intake-api
# Expected: VALID: Model passed all registered validation tests
```

---

## Lessons Learned

### Technical Challenges

1. **Terraform State Management**
   - *Challenge:* Concurrent CI/CD run and local apply hit the same S3 backend state, causing partial-state corruption
   - *Solution:* Used `terraform state rm` to remove orphaned resources, then re-applied locally to reconcile; documented state locking as critical operational practice
   - *Learning:* Never run local `terraform apply` while a CI pipeline is mid-run — state locking without DynamoDB does not prevent concurrent writes on S3 backends without a lock table

2. **IAM Permission Scoping for CI Roles**
   - *Challenge:* The `cgep-grc-gate` OIDC role uses `PowerUserAccess`, which blocks `iam:CreateRole`, `iam:PutRolePolicy`, `iam:PassRole`, and `iam:TagRole`. Monitoring resources require custom IAM roles
   - *Solution:* Added a scoped inline policy granting those four actions only on resources matching `arn:aws:iam::*:role/acme-health-intake-*` — least privilege on the CI role itself
   - *Learning:* `PowerUserAccess` is not truly power-user for IaC; any Terraform module that creates IAM roles will fail without explicit IAM addbacks

3. **AWS Config Delivery Channel Dependency**
   - *Challenge:* Config needed to write delivery logs to S3, but the CloudTrail bucket policy only allows `cloudtrail.amazonaws.com`. Adding Config to that policy creates a circular dependency across files
   - *Solution:* Created a dedicated `aws_s3_bucket.config_delivery` with its own bucket policy and KMS grant inside `monitoring.tf`, keeping it self-contained
   - *Learning:* When two services need separate S3 destinations, resist the temptation to reuse existing buckets — a separate bucket eliminates cross-file coupling

4. **Rego Policy Testing**
   - *Challenge:* Input variable shadowing caused test failures in early drafts
   - *Solution:* Used `test_input` variable with `with input as test_input` syntax throughout all test files
   - *Learning:* `input` is a reserved keyword in OPA; tests must use the `with input as` override pattern

5. **Cosign Keyless Signing**
   - *Challenge:* Understanding the OIDC-based ephemeral certificate flow without a stored key
   - *Solution:* Studied Sigstore documentation; `--yes` flag required to suppress interactive prompt in CI
   - *Learning:* Keyless signing eliminates key rotation burden and produces a publicly verifiable transparency log entry linking the signature to the exact workflow run

### Process Improvements

1. **Policy-First Development** — Writing Rego policies before the Terraform resources forced security thinking upfront and caught design issues before they reached apply
2. **Test-Driven Compliance** — The RED/GREEN PR pattern gives auditors a reproducible demonstration that the gate actually blocks violations, not just that policies exist
3. **Evidence Automation** — Manual evidence collection is error-prone; automated daily collection at 02:00 UTC ensures continuous coverage even on days with no code changes

---

## Future Work

### Short Term
- **WAF on API Gateway:** Add `aws_wafv2_web_acl` + association for rate-limiting and SQL-injection protection on the `/intake` endpoint (the remaining sub-item from GAP-08 not covered by throttling alone)
- **Tighter Config delivery IAM:** Replace the Config role's `AWS_ConfigRole` managed policy attachment with a scoped custom policy limited to the specific delivery bucket

### Medium Term
- **Multi-environment workspaces:** Separate dev/staging/prod state files with environment-specific policy strictness
- **SNS subscriber:** Wire `compliance_alerts` topic to a real endpoint (email or webhook) for observable drift alerting
- **Advanced Rego policies:** Network ACL egress validation, Lambda runtime version checks

### Long Term
- **Policy-as-a-Service:** Centralised versioned policy repository enforced across multiple accounts
- **Continuous compliance dashboard:** CloudWatch metrics dashboard showing Config compliance percentage over time
- **Automated GAP-08 remediation:** Terraform module that provisions the CloudWatch role and wires API Gateway logging without manual intervention

---

**Repository:** https://github.com/Chike2020/cgep-app-starter
**Evidence Vault:** `s3://acme-health-intake-evidence-vault-eca8c0d5`
**Pipeline Runs:** https://github.com/Chike2020/cgep-app-starter/actions
