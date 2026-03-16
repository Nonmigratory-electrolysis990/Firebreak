# Encryption at Rest

## DO

- **Use AES-256-GCM** for symmetric encryption. GCM provides authenticated encryption (confidentiality + integrity) — CBC does not provide integrity without a separate HMAC.
- **Use envelope encryption** — encrypt data with a Data Encryption Key (DEK), encrypt the DEK with a Key Encryption Key (KEK) stored in KMS/HSM. This limits the blast radius of key compromise.
- **Store encryption keys separately from encrypted data**. Keys in KMS/HSM, data in your database. If the database is compromised, the data is still encrypted.
- **Encrypt sensitive columns individually** (SSN, health data, financial data) rather than relying solely on full-disk encryption. FDE protects against physical theft, not application-level breaches.
- **Rotate DEKs periodically** (90 days) and re-encrypt data. KEKs in KMS/HSM should rotate annually at minimum.
- **Use unique DEKs per record or per tenant** where feasible. One compromised key doesn't expose all data.
- **Generate unique IVs/nonces for every encryption operation**. AES-GCM nonce reuse with the same key completely breaks the encryption.
- **Log encryption/decryption operations** at the KMS level for audit. This is your evidence of who accessed what.

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key = AESGCM.generate_key(bit_length=256)
nonce = os.urandom(12)  # MUST be unique per encryption
aead = AESGCM(key)
ciphertext = aead.encrypt(nonce, plaintext, associated_data)
```

## DON'T

- Use AES-ECB mode. ECB reveals patterns in plaintext (the famous "ECB penguin"). Use GCM or CBC+HMAC.
- Reuse IVs/nonces. GCM with a repeated nonce+key pair leaks the authentication key and enables forgery.
- Store encryption keys in the application codebase, config files, or environment variables on the same host as the data.
- Use encryption without authentication (AES-CBC without HMAC). Unauthenticated ciphertext is malleable — attackers can modify it.
- Rely only on transparent disk encryption (dm-crypt, BitLocker, EBS encryption) for application-level security. It protects against stolen disks, not SQL injection.
- Roll your own encryption scheme. Use vetted libraries: `libsodium`, `cryptography` (Python), `ring` (Rust), Web Crypto API.
- Encrypt with a hardcoded key. `AES.encrypt(data, "mysecretkey123")` is not encryption — it's obfuscation.

## Common AI Mistakes

- Using AES-CBC without HMAC, producing malleable ciphertext vulnerable to padding oracle attacks.
- Generating a single nonce/IV at startup and reusing it for all encryption operations.
- Hardcoding the encryption key in the source code: `key = b'0123456789abcdef'`.
- Using `crypto.createCipher()` (deprecated, derives key with MD5) instead of `crypto.createCipheriv()` in Node.js.
- Encrypting the entire database column with a single key and no key rotation plan.
- Confusing Base64 encoding with encryption — encoding is reversible without a key.
