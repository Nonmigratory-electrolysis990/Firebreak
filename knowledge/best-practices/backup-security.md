# Backup Security

## DO

- **Encrypt backups at rest** with AES-256-GCM. Use a dedicated encryption key managed in KMS/HSM, separate from application keys.
- **Encrypt backups in transit**. Use TLS for transfer to offsite storage. Verify certificates — don't disable TLS validation for convenience.
- **Implement access control on backup storage**. Only the backup service account and break-glass emergency accounts should have access. No developer access by default.
- **Rotate backups** with a clear policy: daily for 7 days, weekly for 4 weeks, monthly for 12 months. Automate deletion of expired backups.
- **Store backups offsite** in a different region/provider from production. Same-region backups don't survive regional outages.
- **Test restores regularly** — monthly at minimum. A backup you can't restore is not a backup. Automate restore testing.
- **Exclude secrets** from database backups where possible. API keys, tokens, and credentials in the DB should be re-rotated after a restore, not trusted.
- **Use immutable/WORM storage** (S3 Object Lock, Azure Immutable Blob) to prevent ransomware from deleting backups.
- **Log and alert on backup operations** — creation, access, deletion, and restore. Any unexpected access is a red flag.

## DON'T

- Store backups unencrypted on S3/GCS with default settings. A single misconfigured bucket policy exposes everything.
- Use the same credentials for production database and backup access. Compromise of one shouldn't give both.
- Store backup encryption keys alongside the backups. If the storage is compromised, the key is too.
- Skip restore testing. Teams discover their backup process is broken during the incident they needed it for.
- Keep backups forever without rotation. Old backups contain old vulnerabilities and stale data subject to retention policies.
- Include environment variables, `.env` files, or secret configs in filesystem backups without explicit encryption.

## Common AI Mistakes

- Setting up automated backups to S3 with `aws s3 cp` over plain HTTP (missing `--sse` flag, no encryption).
- Using the production database credentials for the backup script and storing them in a crontab.
- Never implementing restore testing — backups run for months but nobody verifies they're actually restorable.
- Backing up the entire filesystem including `.env`, `credentials.json`, and private keys without extra encryption.
- Not setting lifecycle policies, accumulating terabytes of unrotated backups with mounting storage costs and risk.
- Generating backup encryption keys with `openssl rand` and storing them in a README in the same repo.
