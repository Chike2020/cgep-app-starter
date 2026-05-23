# HIPAA Compliance Automation — Patient Intake API

[![HIPAA Compliance Gate](https://github.com/Chike2020/cgep-app-starter/actions/workflows/hipaa-compliance-gate.yml/badge.svg)](https://github.com/Chike2020/cgep-app-starter/actions/workflows/hipaa-compliance-gate.yml)

**CGE-P Capstone** · Gideon Okechukwu · May 2026  
**Primary framework:** HIPAA Security Rule (45 CFR Part 164)

---

## What this repo is

A GRC baseline wrapped around the `cgep-app-starter` Patient Intake API. It closes 7 of 8 intentional security gaps with Terraform, enforces them with 7 Rego policies via conftest, produces cryptographically signed evidence on every push to `main`, and detects runtime drift daily via AWS Config + EventBridge.

Full design rationale and trade-offs: [`WRITEUP.md`](WRITEUP.md)

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
# OPA unit tests (requires opa in PATH)
opa test policies/hipaa/ -v
# Expected: PASS 17/17

# Terraform validation
cd terraform
terraform init
terraform fmt -check -recursive   # exit 0
terraform validate                 # Success!
terraform test -test-directory=tests/  # 10/10 passed
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

### 5  Validate OSCAL with trestle

```bash
pip install compliance-trestle
mkdir /tmp/trestle-check && cd /tmp/trestle-check
trestle init
trestle import -f /path/to/repo/oscal/component-definition.json -o patient-intake-api
trestle validate -t component-definition -n patient-intake-api
# Expected: VALID: Model passed all registered validation tests
```

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
terraform/            # IaC — KMS, S3 Object Lock vault, CloudTrail, compliance baseline, monitoring
  tests/              # Terraform native integration tests (10/10 pass with mock_provider)
policies/hipaa/       # 7 Rego policies + tests (17/17 OPA tests pass)
oscal/                # OSCAL component-definition.json (trestle-validated)
controls-mapping.csv  # Bidirectional control→code traceability index
.github/workflows/    # hipaa-compliance-gate.yml: Plan → Policy check → Apply → Sign → Upload
WRITEUP.md            # Design rationale, trade-offs, and lessons learned
```
