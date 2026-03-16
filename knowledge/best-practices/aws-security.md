# AWS Security

## DO

- **Apply least-privilege IAM policies**. Start with zero permissions and add only what's needed. Use `Action` and `Resource` explicitly — never `"*"` for both.
- **Enable CloudTrail** in all regions with log file validation. Send logs to a dedicated S3 bucket with MFA delete enabled.
- **Block public S3 access** at the account level with S3 Block Public Access settings. Enable it per-bucket as well.
- **Use KMS customer-managed keys** for encrypting sensitive data at rest (S3, RDS, EBS, DynamoDB). Enable automatic key rotation.
- **Configure VPC security groups** as allowlists — deny all inbound by default, open only required ports to specific CIDR ranges.
- **Enable MFA on the root account** and all IAM users with console access. Use hardware MFA for the root account.
- **Use IAM roles** instead of long-lived access keys. For EC2, use instance profiles. For cross-account access, use `sts:AssumeRole`.

## DON'T

- Use the root account for daily operations. Create IAM users or use AWS SSO.
- Create IAM policies with `"Effect": "Allow", "Action": "*", "Resource": "*"`. This grants god-mode access.
- Make S3 buckets public for "convenience." Use CloudFront with Origin Access Identity for public content.
- Hardcode AWS access keys in application code or commit them to git. Use environment variables, instance profiles, or Secrets Manager.
- Leave default security groups unchanged — the default group allows all outbound and all inbound from itself.
- Disable CloudTrail logging to save costs. It's your audit log and incident response lifeline.
- Use the same IAM credentials across environments (dev/staging/prod). Separate accounts with AWS Organizations.

## Common AI Mistakes

- Creating an IAM policy with `"Action": "s3:*"` and `"Resource": "*"` because "the app needs S3 access."
- Setting an S3 bucket policy to public because the frontend needs to read images — use pre-signed URLs or CloudFront instead.
- Hardcoding `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in a Dockerfile or `docker-compose.yml`.
- Creating a security group with inbound rule `0.0.0.0/0:22` for SSH and leaving it permanently open.
- Putting secrets in SSM Parameter Store as `String` instead of `SecureString`, storing them unencrypted.
