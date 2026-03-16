# Password Storage

## DO

- **Use bcrypt, scrypt, or Argon2id** for hashing. Argon2id is the current recommendation (PHC winner).
- **Set a high work factor**: bcrypt cost 12+, Argon2id with at least 64MB memory and 3 iterations.
- **Use a unique salt per password** — bcrypt and Argon2 handle this automatically.
- **Enforce minimum password length** (8 chars minimum, 12+ recommended). Check against breached password lists (HaveIBeenPwned API).
- **Hash on the server**, not the client. Client-side hashing doesn't protect against replay attacks.

## DON'T

- Use MD5, SHA-1, or SHA-256 for passwords — these are fast hashes, not password hashes. GPUs crack billions per second.
- Store passwords in plaintext or reversible encryption.
- Use a single global salt — if it leaks, all passwords can be attacked in parallel.
- Implement your own password hashing algorithm.
- Log passwords, even in error handlers.
- Limit password maximum length to less than 64 characters.

## Common AI Mistakes

- Using `crypto.createHash('sha256')` for passwords — fast hash, not password hash.
- Storing the password directly: `user.password = req.body.password`.
- Comparing passwords with `===` instead of using the hash library's constant-time compare function.
- Not salting, or using a hardcoded salt value.
