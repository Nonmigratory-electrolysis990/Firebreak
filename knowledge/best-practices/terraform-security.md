# Terraform Security

## DO

- **Encrypt state files at rest**. Use S3 with SSE-KMS, GCS with CMEK, or Azure Blob with encryption. State contains every resource attribute including secrets.
- **Enable state locking** with DynamoDB (AWS), GCS (built-in), or Azure Blob lease. Prevents concurrent applies that corrupt state.
- **Authenticate providers securely**. Use IAM roles, Workload Identity, or Managed Identity — never static credentials in provider blocks.
- **Pin module versions** explicitly: `source = "hashicorp/consul/aws" version = "0.11.0"`. Unpinned modules pull latest, which may contain breaking or malicious changes.
- **Run `terraform plan` in CI** and require human approval before `terraform apply`. Never auto-apply without review.
- **Use `sensitive = true`** on variables and outputs containing secrets. Terraform redacts them from CLI output and logs.
- **Detect drift** by running `terraform plan` on a schedule. Drift between state and reality indicates manual changes or security incidents.

## DON'T

- Store secrets in `terraform.tfvars` or `.tf` files committed to git. Use environment variables (`TF_VAR_*`), Vault, or cloud secret managers.
- Use local state for team projects. Local state can't be locked, shared, or encrypted at rest.
- Use `-auto-approve` in production CI/CD without a prior plan review step.
- Output sensitive values without `sensitive = true` — they appear in plaintext in logs, state, and `terraform output`.
- Use `terraform import` without immediately running `plan` to verify the imported resource matches your config.
- Pin providers to `~>` major versions (`~> 5.0`). Pin to minor versions (`~> 5.25.0`) for stability.
- Commit `.terraform.lock.hcl` changes without reviewing what provider versions changed.

## Common AI Mistakes

- Putting `access_key` and `secret_key` directly in the AWS provider block.
- Using local state (`terraform.tfstate` on disk) in all examples without mentioning remote backends.
- Creating an S3 bucket for state with default settings — no encryption, no versioning, no access logging.
- Defining `variable "db_password" {}` without `sensitive = true`, exposing it in plan output.
- Writing `module "vpc" { source = "terraform-aws-modules/vpc/aws" }` with no version constraint.
