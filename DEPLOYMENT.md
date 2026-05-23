\# Deployment Guide \& Technical Runbook



This document explains how to deploy, operate, and troubleshoot the HIPAA compliance automation system in production.



\---



\## Table of Contents



1\. \[Prerequisites \& Setup](#prerequisites--setup)

2\. \[Local Development Workflow](#local-development-workflow)

3\. \[CI/CD Pipeline Operation](#cicd-pipeline-operation)

4\. \[Troubleshooting Guide](#troubleshooting-guide)

5\. \[Disaster Recovery](#disaster-recovery)

6\. \[Operational Procedures](#operational-procedures)



\---



\## Prerequisites \& Setup



\### Required Tools



```bash

\# Terraform

terraform --version  # Requires 1.9.0+



\# OPA

opa version  # Requires 0.55.0+



\# AWS CLI

aws --version  # Requires 2.x



\# Cosign (optional for local signing)

cosign version

```



\### AWS Authentication



\*\*Why OIDC instead of access keys?\*\*



Traditional approach: Store `AWS\_ACCESS\_KEY\_ID` and `AWS\_SECRET\_ACCESS\_KEY` as GitHub secrets.



\*\*Problems:\*\*

\- Long-lived credentials (compromised secrets stay valid until rotated)

\- No automatic rotation

\- Manual key management overhead

\- Violates zero-trust principle (credential == full access)



\*\*OIDC approach:\*\*

\- GitHub Actions requests a token from AWS STS using OIDC

\- Token is valid for 1 hour only (automatic expiration)

\- No stored credentials (nothing to leak)

\- Trust is federated through identity provider



\*\*Setup:\*\*



The OIDC provider and IAM role are already configured in `terraform/github-oidc.tf`:



```hcl

resource "aws\_iam\_openid\_connect\_provider" "github" {

&#x20; url = "https://token.actions.githubusercontent.com"

&#x20; client\_id\_list = \["sts.amazonaws.com"]

&#x20; # Thumbprints verify the OIDC provider's certificate

&#x20; thumbprint\_list = \[

&#x20;   "6938fd4d98bab03faadb97b34396831e3780aea1",

&#x20;   "1c58a3a8518e8759bf075b76b750d4f2df264fcd"

&#x20; ]

}



resource "aws\_iam\_role" "github\_actions" {

&#x20; name = "cgep-grc-gate"

&#x20; assume\_role\_policy = jsonencode({

&#x20;   Statement = \[{

&#x20;     Effect = "Allow"

&#x20;     Principal = {

&#x20;       Federated = aws\_iam\_openid\_connect\_provider.github.arn

&#x20;     }

&#x20;     Action = "sts:AssumeRoleWithWebIdentity"

&#x20;     Condition = {

&#x20;       StringEquals = {

&#x20;         "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"

&#x20;       }

&#x20;       StringLike = {

&#x20;         # Only this specific repo can assume the role

&#x20;         "token.actions.githubusercontent.com:sub" = "repo:Chike2020/cgep-app-starter:\*"

&#x20;       }

&#x20;     }

&#x20;   }]

&#x20; })

}

```



\*\*The authentication flow:\*\*



1\. GitHub Actions starts workflow

2\. Requests OIDC token from GitHub (token contains repo identity)

3\. Calls AWS STS AssumeRoleWithWebIdentity with token

4\. AWS verifies token signature, checks conditions

5\. Returns temporary credentials (valid 1 hour)

6\. Pipeline uses credentials for Terraform operations



\*\*Security properties:\*\*

\- Zero standing credentials

\- Automatic expiration

\- Scoped to specific repository

\- Auditable (CloudTrail logs all STS AssumeRole calls)



\---



\## Local Development Workflow



\### First-Time Setup



```bash

\# Clone repository

git clone https://github.com/Chike2020/cgep-app-starter

cd cgep-app-starter/terraform



\# Initialize Terraform (downloads providers, configures backend)

terraform init



\# This connects to S3 backend

\# If state doesn't exist, Terraform creates it

\# If state exists, Terraform downloads it

```



\*\*What `terraform init` does:\*\*



1\. \*\*Downloads provider plugins\*\* (aws, random, archive) to `.terraform/providers/`

2\. \*\*Configures S3 backend:\*\*

&#x20;  - Checks if `acme-health-intake-evidence-vault-eca8c0d5` bucket exists

&#x20;  - Looks for `terraform/state/terraform.tfstate` key

&#x20;  - If found, downloads state file to local cache

3\. \*\*Creates DynamoDB lock table\*\* (if configured) to prevent concurrent runs



\*\*Why backend configuration matters:\*\*



Without S3 backend, local runs use `terraform.tfstate` file on disk. Problems:

\- Each developer has their own state file (divergence)

\- CI/CD doesn't know what's deployed (tries to recreate everything)

\- No team collaboration (can't share state)



With S3 backend, everyone reads/writes the same state:

\- Local dev sees production resources

\- CI/CD applies changes incrementally

\- State is versioned (can rollback if corrupted)



\### Development Cycle



```bash

\# 1. Make changes to Terraform files

vim main.tf



\# 2. Check what will change

terraform plan



\# Example output:

\# Terraform will perform the following actions:

\#   # aws\_s3\_bucket.new\_bucket will be created

\#   + resource "aws\_s3\_bucket" "new\_bucket" {

\#       + bucket = "new-bucket-name"

\#       + tags   = { DataClass = "phi" }

\#     }

\# Plan: 1 to add, 0 to change, 0 to destroy.



\# 3. Generate JSON plan for policy testing

terraform plan -out=tfplan

terraform show -json tfplan > plan.json



\# 4. Test policies locally

cd ../policies/hipaa

opa test . -v



\# 5. Run policies against the plan

conftest test ../../terraform/plan.json -p . --all-namespaces



\# If violations found:

\# FAIL - compliance.hipaa.s3\_kms\_encryption

\# HIPAA 164.312(a)(2)(iv) VIOLATION: ...



\# Fix violations, re-run steps 2-5 until clean



\# 6. Apply changes

cd ../../terraform

terraform apply tfplan



\# 7. Commit and push

git add .

git commit -m "Add new PHI bucket with KMS encryption"

git push

```



\*\*Why generate plan.json?\*\*



Terraform plans are binary files (`.tfplan`). Rego policies need structured data. `terraform show -json tfplan` converts binary plan to JSON that OPA can parse.



\*\*Why test policies locally?\*\*



Faster feedback loop:

\- Local test: 1-2 seconds

\- CI/CD pipeline: 20-30 seconds (setup overhead)



Catch violations before pushing, avoiding "fix commit" spam.



\---



\## CI/CD Pipeline Operation



\### Pipeline Trigger Conditions



\*\*Pull Requests:\*\*

```yaml

on:

&#x20; pull\_request:

&#x20;   branches: \[main]

```



Runs: Plan → Policy Check (STOPS HERE, no apply)



\*\*Why no apply on PRs?\*\* PRs are proposals, not approved changes. We validate but don't deploy.



\*\*Pushes to Main:\*\*

```yaml

on:

&#x20; push:

&#x20;   branches: \[main]

```



Runs: Plan → Policy Check → Apply → Sign → Upload



\*\*Why apply on push?\*\* Main branch represents approved changes (merged PRs). Safe to deploy.



\### Pipeline Steps Explained



\*\*Step 1: Terraform Plan\*\*



```yaml

\- name: Terraform Plan

&#x20; working-directory: ./terraform

&#x20; run: |

&#x20;   terraform plan -out=tfplan

&#x20;   terraform show -json tfplan > plan.json

```



\*\*What this does:\*\*

\- Compares desired state (Terraform files) vs actual state (AWS resources)

\- Generates execution plan showing creates/updates/deletes

\- Saves plan to `tfplan` (binary) and `plan.json` (JSON)



\*\*Why save the plan?\*\*

\- Policy check needs JSON representation

\- `terraform apply tfplan` ensures applied changes match what was reviewed



\*\*Step 2: Policy Check\*\*



```yaml

\- name: Policy Check (Conftest)

&#x20; working-directory: ./terraform

&#x20; run: |

&#x20;   conftest test plan.json -p ../policies/hipaa/ --all-namespaces

```



\*\*What `--all-namespaces` means:\*\*



Rego policies are organized in namespaces (packages):

\- `compliance.hipaa.s3\_kms\_encryption`

\- `compliance.hipaa.dynamodb\_kms`

\- etc.



Without `--all-namespaces`, Conftest only loads `main` package. This flag loads all packages in the directory.



\*\*Exit codes:\*\*

\- 0 = All policies passed (continue pipeline)

\- 1 = At least one policy failed (block pipeline)



\*\*Why this is fail-closed:\*\*



GitHub Actions interprets exit code 1 as failure. Pipeline stops, PR cannot merge. Developer must fix violations before proceeding.



\*\*Step 3: Terraform Apply\*\* (main branch only)



```yaml

\- name: Terraform Apply

&#x20; if: github.ref == 'refs/heads/main' \&\& github.event\_name == 'push'

&#x20; working-directory: ./terraform

&#x20; run: terraform apply -auto-approve tfplan

```



\*\*Why `if` condition?\*\*

\- `github.ref == 'refs/heads/main'`: Only on main branch (not PRs)

\- `github.event\_name == 'push'`: Only on push (not PR preview)



\*\*Why `-auto-approve`?\*\*



In CI/CD, there's no human to type "yes". But we've already validated:

\- Plan was reviewed (PR approval)

\- Policies passed (Step 2)



Auto-approve is safe because we're applying a pre-reviewed plan.



\*\*What if apply fails?\*\*



Pipeline exits with error. Evidence bundle is NOT created (no signing, no upload). This prevents incomplete deployments from being recorded as successful.



\*\*Step 4: Sign Evidence\*\*



```yaml

\- name: Bundle and Sign Evidence

&#x20; run: |

&#x20;   mkdir -p evidence

&#x20;   cp plan.json evidence/

&#x20;   tar -czf evidence-${{ github.run\_id }}-${{ github.sha }}.tar.gz evidence/

&#x20;   sha256sum evidence-\*.tar.gz | awk '{print $1}' > evidence-\*.tar.gz.sha256

&#x20;   cosign sign-blob evidence-\*.tar.gz --bundle evidence-\*.tar.gz.sig.bundle --yes

```



\*\*Why include `run\_id` and `sha` in filename?\*\*



\- `run\_id`: Unique pipeline execution ID (e.g., 26318352453)

\- `sha`: Git commit hash (e.g., 4d64658e...)



Together, they create a unique identifier linking:

\- Pipeline run → GitHub Actions URL

\- Git commit → Code changes

\- Evidence bundle → Proof of enforcement



\*\*What `--yes` does:\*\*



Cosign normally prompts: "Sign using ephemeral key? (y/n)". In CI/CD, we can't interact, so `--yes` auto-confirms.



\*\*Step 5: Upload to Vault\*\*



```yaml

\- name: Upload to Evidence Vault

&#x20; run: |

&#x20;   VAULT\_BUCKET="acme-health-intake-evidence-vault-eca8c0d5"

&#x20;   RUN\_PATH="runs/${{ github.run\_id }}"

&#x20;   aws s3 cp evidence-\*.tar.gz "s3://$VAULT\_BUCKET/$RUN\_PATH/"

&#x20;   aws s3 cp evidence-\*.tar.gz.sha256 "s3://$VAULT\_BUCKET/$RUN\_PATH/"

&#x20;   aws s3 cp evidence-\*.tar.gz.sig.bundle "s3://$VAULT\_BUCKET/$RUN\_PATH/"

&#x20;   aws s3 cp receipt.json "s3://$VAULT\_BUCKET/$RUN\_PATH/"

```



\*\*Why separate files instead of one tarball?\*\*



Allows selective verification:

1\. Auditor downloads signature bundle only (8 KB vs 70 KB tarball)

2\. Verifies signature against public Rekor log

3\. Only if signature valid, downloads full tarball

4\. Verifies hash matches



This saves bandwidth and allows signature verification without downloading evidence.



\*\*Storage class:\*\*



Default is STANDARD. Could optimize with INTELLIGENT\_TIERING (auto-moves to cheaper storage after 30 days). For 90-day retention, STANDARD is fine.



\---



\## Troubleshooting Guide



\### Policy Test Failures



\*\*Symptom:\*\* `opa test . -v` shows failures



\*\*Common causes:\*\*



\*\*1. Input shadowing:\*\*

```rego

test\_example if {

&#x20;   input := {"foo": "bar"}  # ERROR: can't redefine 'input'

&#x20;   deny == {}

}

```



\*\*Fix:\*\*

```rego

test\_example if {

&#x20;   test\_input := {"foo": "bar"}

&#x20;   result := deny with input as test\_input

&#x20;   count(result) == 0

}

```



\*\*Why this happens:\*\* `input` is a reserved keyword in Rego. Tests must use `with input as` syntax.



\*\*2. JSON parsing errors:\*\*



```rego

has\_tls\_policy(bucket\_name) if {

&#x20;   policy := json.unmarshal(resource.change.after.policy)

&#x20;   # If policy is invalid JSON, this line fails silently

}

```



\*\*Fix:\*\* Add error handling or validate JSON structure:

```rego

has\_tls\_policy(bucket\_name) if {

&#x20;   policy\_str := resource.change.after.policy

&#x20;   policy := json.unmarshal(policy\_str)

&#x20;   # Check that policy.Statement exists before accessing it

&#x20;   count(policy.Statement) > 0

}

```



\*\*3. Array access without bounds checking:\*\*



```rego

has\_versioning(bucket\_name) if {

&#x20;   resource.change.after.versioning\_configuration\[0].status == "Enabled"

&#x20;   # Fails if versioning\_configuration is empty

}

```



\*\*Fix:\*\*

```rego

has\_versioning(bucket\_name) if {

&#x20;   resource.change.after.versioning\_configuration\[\_].status == "Enabled"

&#x20;   # \[\_] means "any element" - safer than \[0]

}

```



\---



\### Pipeline Failures



\*\*Symptom:\*\* GitHub Actions workflow fails at "Terraform Init"



\*\*Error:\*\*



Error: Failed to get existing workspaces: S3 bucket does not exist.



\*\*Cause:\*\* S3 backend bucket doesn't exist or isn't accessible.



\*\*Fix:\*\*

1\. Verify bucket exists: `aws s3 ls s3://acme-health-intake-evidence-vault-eca8c0d5`

2\. Check IAM permissions on `cgep-grc-gate` role

3\. Verify OIDC trust relationship allows this repository



\---



\*\*Symptom:\*\* Policy check passes locally but fails in CI/CD



\*\*Possible causes:\*\*



\*\*1. Different policy versions:\*\*



Local: `policies/hipaa/gap01\_s3\_kms\_encryption.rego` (uncommitted changes)

CI/CD: Clones from Git (doesn't have local changes)



\*\*Fix:\*\* Commit and push policy files before testing.



\*\*2. Different Terraform versions:\*\*



Local: Terraform 1.6.0

CI/CD: Terraform 1.9.0 (workflow specifies version)



Plan JSON structure might differ between versions.



\*\*Fix:\*\* Pin Terraform version locally to match CI/CD:

```bash

tfenv install 1.9.0

tfenv use 1.9.0

```



\---



\*\*Symptom:\*\* Cosign signing fails with "Failed to fetch OIDC token"



\*\*Error:\*\*

Error: getting signer: getting OIDC token: unable to fetch token



\*\*Cause:\*\* GitHub Actions OIDC permissions not configured.



\*\*Fix:\*\* Verify workflow has `id-token: write` permission:

```yaml

permissions:

&#x20; id-token: write  # Required for Cosign keyless signing

&#x20; contents: read

```



Without this, GitHub refuses to issue OIDC tokens to the workflow.



\---



\### State Lock Errors



\*\*Symptom:\*\*

Error: Error acquiring the state lock

Lock Info:

ID:        abc123-def456...

Path:      terraform/state/terraform.tfstate

Operation: OperationTypeApply

Who:       runner@fv-az123

Version:   1.9.0

Created:   2026-05-23 01:30:00 UTC



\*\*Cause:\*\* Two processes tried to modify state simultaneously (e.g., local run + CI/CD run).



\*\*How locking works:\*\*



When Terraform runs, it:

1\. Creates a lock entry in DynamoDB (table: `terraform-state-lock`)

2\. Performs plan/apply

3\. Releases lock



If another process tries to run, it sees the lock and waits (or fails after timeout).



\*\*Fix:\*\*



\*\*If lock is stale\*\* (previous run crashed without releasing lock):

```bash

terraform force-unlock abc123-def456

```



\*\*If lock is active\*\* (another legitimate run):

Wait for it to complete. Don't force-unlock an active run—you'll corrupt state.



\*\*Prevention:\*\*



Don't run local `terraform apply` while CI/CD is running. Coordinate deployments or use Terraform workspaces for isolation.



\---



\## Disaster Recovery



\### Scenario 1: State File Corrupted



\*\*Detection:\*\*

```bash

terraform plan

\# Error: Failed to load state: state snapshot was created by Terraform v1.9.0

\# but this is v1.8.0; please upgrade

```



\*\*Recovery:\*\*



S3 versioning saves us. List previous versions:

```bash

aws s3api list-object-versions \\

&#x20; --bucket acme-health-intake-evidence-vault-eca8c0d5 \\

&#x20; --prefix terraform/state/terraform.tfstate

```



Output:

```json

{

&#x20; "Versions": \[

&#x20;   {"VersionId": "current", "LastModified": "2026-05-23T01:00:00Z"},

&#x20;   {"VersionId": "v123", "LastModified": "2026-05-22T23:00:00Z"},

&#x20;   {"VersionId": "v122", "LastModified": "2026-05-22T22:00:00Z"}

&#x20; ]

}

```



Restore previous version:

```bash

aws s3api copy-object \\

&#x20; --copy-source acme-health-intake-evidence-vault-eca8c0d5/terraform/state/terraform.tfstate?versionId=v123 \\

&#x20; --bucket acme-health-intake-evidence-vault-eca8c0d5 \\

&#x20; --key terraform/state/terraform.tfstate

```



Test recovery:

```bash

terraform plan  # Should succeed now

```



\*\*Why versioning is critical:\*\*



Without it, a corrupted state file is permanent. You'd need to:

1\. Manually inventory all AWS resources

2\. Import them one-by-one into Terraform

3\. Hope you didn't miss anything



With versioning, recovery is one S3 copy command.



\---



\### Scenario 2: Accidental `terraform destroy`



\*\*Detection:\*\*

Destroy complete! Resources: 50 destroyed.



\*\*Immediate action:\*\*



1\. \*\*Don't panic and re-apply.\*\* State file still references destroyed resources.



2\. Check CloudTrail for who/when:

```bash

aws cloudtrail lookup-events \\

&#x20; --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteBucket \\

&#x20; --max-results 50

```



3\. Restore from evidence vault:



Every pipeline run stores:

\- `plan.json` (what was supposed to be deployed)

\- `tfplan` (binary plan with full configuration)



Extract last known good plan:

```bash

\# Download last successful run

aws s3 cp s3://acme-health-intake-evidence-vault-eca8c0d5/runs/26318352453/evidence-\*.tar.gz .



\# Extract

tar -xzf evidence-\*.tar.gz



\# Review plan

terraform show -json evidence/tfplan > recovered-plan.json

```



4\. Re-apply configuration:

```bash

\# State is empty (everything destroyed)

\# Run apply to recreate from code

terraform apply

```



\*\*Data loss assessment:\*\*



\- \*\*Infrastructure:\*\* Fully recovered (code in Git)

\- \*\*State:\*\* Fully recovered (versioned in S3)

\- \*\*Application data:\*\* Depends on backups

&#x20; - DynamoDB: Point-in-time recovery (35 days)

&#x20; - S3: Versioning enabled (can restore deleted objects)



\*\*Prevention:\*\*



1\. Require MFA for `terraform destroy` in production

2\. Use Terraform Cloud with run confirmations

3\. Implement SCPs preventing deletion of critical resources



\---



\## Operational Procedures



\### Adding a New Policy



\*\*Scenario:\*\* Need to enforce Lambda memory limits (cost control).



\*\*Step 1: Write policy\*\*



```bash

cd policies/hipaa

vim gap09\_lambda\_memory.rego

```



```rego

package compliance.cost.lambda\_memory



import rego.v1



deny contains msg if {

&#x20;   some resource in input.resource\_changes

&#x20;   resource.type == "aws\_lambda\_function"

&#x20;   resource.change.after.memory\_size > 3008  # Max allowed

&#x20;   

&#x20;   msg := sprintf(

&#x20;       "Cost policy violation: Lambda '%s' requests %d MB memory (max: 3008 MB)",

&#x20;       \[resource.change.after.function\_name, resource.change.after.memory\_size]

&#x20;   )

}

```



\*\*Step 2: Write tests\*\*



```bash

vim gap09\_lambda\_memory\_test.rego

```



```rego

package compliance.cost.lambda\_memory



import rego.v1



test\_lambda\_within\_limit\_passes if {

&#x20;   test\_input := {

&#x20;       "resource\_changes": \[{

&#x20;           "type": "aws\_lambda\_function",

&#x20;           "change": {

&#x20;               "after": {

&#x20;                   "function\_name": "small-function",

&#x20;                   "memory\_size": 512

&#x20;               }

&#x20;           }

&#x20;       }]

&#x20;   }

&#x20;   

&#x20;   result := deny with input as test\_input

&#x20;   count(result) == 0

}



test\_lambda\_exceeds\_limit\_fails if {

&#x20;   test\_input := {

&#x20;       "resource\_changes": \[{

&#x20;           "type": "aws\_lambda\_function",

&#x20;           "change": {

&#x20;               "after": {

&#x20;                   "function\_name": "huge-function",

&#x20;                   "memory\_size": 10240  # Exceeds limit

&#x20;               }

&#x20;           }

&#x20;       }]

&#x20;   }

&#x20;   

&#x20;   result := deny with input as test\_input

&#x20;   count(result) == 1

}

```



\*\*Step 3: Test locally\*\*



```bash

opa test . -v

\# Should show 2 new tests passing

```



\*\*Step 4: Test against real Terraform plan\*\*



```bash

cd ../../terraform



\# Create test Lambda

cat > test-lambda.tf <<EOF

resource "aws\_lambda\_function" "test" {

&#x20; function\_name = "test-large-memory"

&#x20; memory\_size   = 5000  # Intentionally violates policy

&#x20; # ... other required fields

}

EOF



terraform plan -out=tfplan

terraform show -json tfplan > plan.json



cd ../policies/hipaa

conftest test ../../terraform/plan.json -p . --all-namespaces

```



Expected output:

FAIL - compliance.cost.lambda\_memory

Cost policy violation: Lambda 'test-large-memory' requests 5000 MB memory (max: 3008 MB)



\*\*Step 5: Clean up test, commit policy\*\*



```bash

cd ../../terraform

rm test-lambda.tf



git add ../policies/hipaa/gap09\_lambda\_memory\*

git commit -m "Add Lambda memory limit policy for cost control"

git push

```



\*\*Step 6: Update documentation\*\*



Add to `WRITEUP.md` under "Policy Enforcement" section.



\---



\### Rotating Evidence Vault Credentials



\*\*When:\*\* Every 90 days or on suspected compromise.



\*\*Why:\*\* Defense in depth. Even though OIDC uses temporary credentials, rotating the IAM role limits exposure window.



\*\*Procedure:\*\*



\*\*1. Create new IAM role:\*\*



```bash

cd terraform

vim github-oidc-v2.tf

```



```hcl

resource "aws\_iam\_role" "github\_actions\_v2" {

&#x20; name = "cgep-grc-gate-v2"

&#x20; # ... same config as v1

}

```



\*\*2. Apply:\*\*



```bash

terraform apply

\# Creates new role, keeps old role running

```



\*\*3. Update workflow to use new role:\*\*



```bash

cd ../.github/workflows

vim hipaa-compliance-gate.yml

```



Change:

```yaml

role-to-assume: arn:aws:iam::973191046894:role/cgep-grc-gate-v2

```



\*\*4. Test new role:\*\*



```bash

git checkout -b test-new-oidc-role

git add .

git commit -m "Rotate OIDC role to v2"

git push -u origin test-new-oidc-role

```



Create PR, verify pipeline succeeds.



\*\*5. Merge and delete old role:\*\*



After 24 hours with no issues:



```bash

cd terraform

vim github-oidc.tf  # Remove old role

terraform apply

```



\*\*Why 24-hour wait?\*\*



Gives time to catch issues:

\- In-flight deployments using old role

\- Cached credentials (shouldn't happen with OIDC, but defensive)

\- Monitoring alerts



\---



\### Reviewing Evidence for Audit



\*\*Scenario:\*\* Auditor asks: "Prove that HIPAA encryption policy was enforced on February 15th, 2026."



\*\*Step 1: Find relevant pipeline run\*\*



```bash

\# Search GitHub Actions runs for date

gh run list --created "2026-02-15" --json databaseId,conclusion,createdAt

```



Output:

```json

\[

&#x20; {"databaseId": 12345678, "conclusion": "success", "createdAt": "2026-02-15T10:30:00Z"}

]

```



\*\*Step 2: Download evidence bundle\*\*



```bash

aws s3 cp s3://acme-health-intake-evidence-vault-eca8c0d5/runs/12345678/ . --recursive

```



Downloads:

\- `evidence-12345678-{sha}.tar.gz`

\- `evidence-12345678-{sha}.tar.gz.sha256`

\- `evidence-12345678-{sha}.tar.gz.sig.bundle`

\- `receipt.json`



\*\*Step 3: Verify signature\*\*



```bash

cosign verify-blob \\

&#x20; --bundle evidence-\*.tar.gz.sig.bundle \\

&#x20; --certificate-identity-regexp="https://github.com/Chike2020/cgep-app-starter" \\

&#x20; --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \\

&#x20; evidence-\*.tar.gz

```



Output:

Verified OK

Certificate subject: https://github.com/Chike2020/cgep-app-starter/.github/workflows/hipaa-compliance-gate.yml@refs/heads/main



\*\*This proves:\*\*

\- Evidence bundle is authentic (signed by our workflow)

\- Bundle hasn't been tampered with (signature validates)

\- Signature was created on February 15th (check Rekor log)



\*\*Step 4: Extract and review plan\*\*



```bash

tar -xzf evidence-\*.tar.gz

terraform show -json evidence/plan.json | jq '.resource\_changes\[] | select(.type == "aws\_s3\_bucket")'

```



Shows all S3 buckets in the plan. Check for KMS encryption config.



\*\*Step 5: Show policy evaluation\*\*



Evidence bundle doesn't include Conftest output. But we can recreate it:



```bash

\# Get policies from Git at that commit

git checkout {sha}

conftest test evidence/plan.json -p policies/hipaa/ --all-namespaces

```



Output:

6 tests, 6 passed, 0 warnings, 0 failures



\*\*Present to auditor:\*\*

\- ✅ Evidence bundle (cryptographically authentic)

\- ✅ Signature verification (proves non-repudiation)

\- ✅ Policy evaluation (shows enforcement)

\- ✅ Terraform plan (shows what was deployed)



\*\*This satisfies audit requirements for:\*\*

\- HIPAA 164.308(a)(1)(ii)(D) - Information system activity review

\- SOC 2 CC7.2 - System monitoring

\- ISO 27001 A.12.4.1 - Event logging



\---



\## Performance Optimization



\### Reducing Pipeline Runtime



\*\*Current:\*\* \~30 seconds per run



\*\*Bottlenecks:\*\*



1\. \*\*Terraform Init\*\* (\~5 seconds)

&#x20;  - Downloads providers (90 MB)

&#x20;  - Configures backend



2\. \*\*Terraform Plan\*\* (\~10 seconds)

&#x20;  - Reads state from S3

&#x20;  - Queries AWS APIs for drift detection



3\. \*\*Policy Check\*\* (\~2 seconds)

&#x20;  - Loads 6 policies

&#x20;  - Evaluates against plan



4\. \*\*Terraform Apply\*\* (\~10 seconds)

&#x20;  - Creates/updates resources

&#x20;  - Writes state to S3



\*\*Optimizations:\*\*



\*\*1. Cache provider plugins:\*\*



```yaml

\- name: Cache Terraform plugins

&#x20; uses: actions/cache@v3

&#x20; with:

&#x20;   path: \~/.terraform.d/plugin-cache

&#x20;   key: terraform-${{ hashFiles('\*\*/.terraform.lock.hcl') }}

```



Saves: \~3 seconds (Init downloads from cache, not internet)



\*\*2. Use Terraform Cloud remote backend:\*\*



Terraform Cloud stores state in managed infrastructure with CDN caching. Faster than direct S3 access.



Trade-off: Adds monthly cost ($20/user).



\*\*3. Parallelize policy evaluation:\*\*



Currently, Conftest evaluates policies serially. Could split into multiple jobs:



```yaml

policy-check:

&#x20; strategy:

&#x20;   matrix:

&#x20;     policy: \[gap01, gap02, gap03, gap04, gap05, gap07]

&#x20; steps:

&#x20;   - run: conftest test plan.json -p policies/hipaa/${{ matrix.policy }}.rego

```



Saves: \~1 second (policies run in parallel)



Trade-off: More complex workflow, harder to debug.



\*\*Net savings:\*\* \~4 seconds (30s → 26s). Marginal benefit for added complexity.



\*\*Recommendation:\*\* Keep simple workflow. 30 seconds is acceptable for compliance gates.



\---



\## Appendix: Advanced Configurations



\### Multi-Environment Setup



\*\*Goal:\*\* Separate dev/staging/prod with different policy strictness.



\*\*Approach 1: Terraform Workspaces\*\*



```bash

terraform workspace new dev

terraform workspace new staging

terraform workspace new prod

```



Each workspace has separate state file:

\- `terraform/state/dev/terraform.tfstate`

\- `terraform/state/staging/terraform.tfstate`

\- `terraform/state/prod/terraform.tfstate`



\*\*Approach 2: Directory Structure\*\*

terraform/

├── modules/

│   └── patient-intake-api/

├── environments/

│   ├── dev/

│   │   ├── main.tf

│   │   └── backend.tf

│   ├── staging/

│   └── prod/



Each environment calls shared modules with different variables.



\*\*Policy differences:\*\*



```rego

\# In dev, allow unencrypted buckets for testing

deny contains msg if {

&#x20;   is\_phi\_bucket(resource)

&#x20;   not has\_kms\_encryption(bucket\_name)

&#x20;   # Only enforce in production

&#x20;   environment := input.terraform\_workspace

&#x20;   environment == "prod"

}

```



\*\*Trade-off:\*\* Adds complexity. Start with single environment, split when needed.



\---



\*\*End of Deployment Guide\*\*

