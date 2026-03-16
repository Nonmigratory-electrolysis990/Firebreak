# Key Management

## DO

- **Use a dedicated KMS** (AWS KMS, GCP Cloud KMS, Azure Key Vault, HashiCorp Vault) for key storage and operations. Keys should never exist in plaintext outside the KMS.
- **Implement a key hierarchy**: root keys (in HSM) > key encryption keys (KEKs) > data encryption keys (DEKs). Compromise of a DEK doesn't expose the root.
- **Use envelope encryption** — generate DEKs locally, encrypt them with a KEK in KMS, store the encrypted DEK alongside the ciphertext. Decrypt the DEK via KMS only when needed.
- **Rotate keys on a schedule**: DEKs every 90 days, KEKs annually, root keys per HSM vendor guidance. Automate rotation.
- **Support key versioning** — when rotating, keep old key versions available for decryption but use only the latest for encryption. Migrate data progressively.
- **Restrict key access with IAM policies** — principle of least privilege. Separate permissions for encrypt, decrypt, and admin operations.
- **Audit all key operations** — KMS access logs show who encrypted/decrypted what and when. Enable and monitor these logs.
- **Plan for key compromise** — document the rotation procedure before you need it. Who rotates, how fast, what data needs re-encryption.

```python
# Envelope encryption with AWS KMS
import boto3
kms = boto3.client('kms')

# Generate a data key
response = kms.generate_data_key(KeyId='alias/my-key', KeySpec='AES_256')
plaintext_dek = response['Plaintext']      # Use this to encrypt data
encrypted_dek = response['CiphertextBlob'] # Store this alongside encrypted data

# Later: decrypt the DEK to decrypt data
response = kms.decrypt(CiphertextBlob=encrypted_dek)
plaintext_dek = response['Plaintext']
```

## DON'T

- Hardcode encryption keys in source code, config files, or environment variables. Use KMS/Vault.
- Store keys alongside the data they protect. Encrypted database + key in the same S3 bucket = plaintext with extra steps.
- Generate keys with `Math.random()`, `rand()`, or any non-cryptographic PRNG. Use `crypto.randomBytes()`, `/dev/urandom`, or KMS key generation.
- Share encryption keys across environments (dev/staging/prod). Each environment gets its own keys.
- Email, Slack, or commit encryption keys. Use KMS/Vault APIs for key distribution.
- Manage keys manually without rotation. Manual processes guarantee stale keys and forgotten rotations.
- Use a single key for all data. If it's compromised, everything is exposed.

## Common AI Mistakes

- Generating an AES key with `crypto.randomBytes(32)` and hardcoding it as a constant in the source code.
- Storing the encryption key in the same database table as the encrypted data.
- Implementing key rotation that generates a new key but never re-encrypts existing data with it.
- Using `process.env.ENCRYPTION_KEY` without any KMS — the key sits in plaintext in the deployment config.
- Skipping key versioning, making rotation a breaking change that requires immediate re-encryption of all data.
- Not setting up KMS access logging, making it impossible to investigate key usage during an incident.
