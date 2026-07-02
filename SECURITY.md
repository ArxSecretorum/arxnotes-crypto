# Security Policy — Arx Notes `:crypto`

## Audit status (read this first)

This module is covered by its own automated test suite (73 tests, including RFC 5869 and
RFC 9106 known-answer vectors) and an internal self-assessment. **No independent external
security audit has been performed.** Do not interpret anything in this repository as
third-party validation. Independent review is explicitly welcomed —
[AUDIT-SCOPE.md](AUDIT-SCOPE.md) provides a ready map to make such a review fast.

## Reporting a vulnerability

Please report security issues **privately** — do **not** open a public issue or PR containing
a working exploit.

- **Preferred:** GitHub *private security advisory* — the repository **Security** tab →
  **Report a vulnerability**.
- **Alternative:** e-mail the maintainer security contact: 
  `arx.secretorum@gmail.com`

Please include the affected file/function, reproduction steps or a PoC, and the impact.
We aim to acknowledge within a reasonable time and will credit reporters who wish to be named.
Coordinated disclosure is appreciated.

## Assets protected

- Note and task contents (in the SQLCipher-encrypted database).
- Voice-note audio (encrypted files).
- The lock PIN — stored only as a one-way Argon2id hash, never in a recoverable form.
- Backup files exported via SAF.

## What we defend against

| Threat | Defense |
|---|---|
| Access to app files **without unlocking the device** (lost/stolen powered-off or locked phone, memory-chip extraction) | DB/audio encrypted with a key derived from a master wrapped by **Android Keystore**; the wrap key is non-exportable and `setUnlockedDeviceRequired(true)` makes it unusable while locked. |
| Reading the DB file with a third-party SQLite client | SQLCipher: the file is unreadable without the key. |
| Theft/interception of a backup file | Argon2id (memory-hard KDF) + AES-256-GCM; brute force is expensive, tamper fails the GCM tag. |
| Tampering with / corrupting encrypted data | Authenticated encryption (GCM tag) everywhere; modification → decryption returns an error/`null`. |
| Leak of a single working subkey | HKDF separation: does not expose the master or other subkeys. |

## Out of scope (NOT defended)

- Compromised/rooted device, or active malware with process privileges (can read keys in the running app's memory).
- An unlocked device in an attacker's hands when app-lock is disabled (the lock is optional).
- A weak backup password — Argon2id raises brute-force cost but cannot save trivial passwords.
- Forensic RAM dump of the running process (keys/plaintext are unavoidably present in memory while running).
- Metadata: file sizes, modification times, the fact that notes/audio exist.
- OS/UI side channels: screenshots, clipboard, keyboard loggers, OS backup.
- **Reminder text in an AlarmManager `PendingIntent`** — to render a notification on the lock
  screen the task text must be available without the DB (which is unavailable while the device
  is locked). It is held in the system AlarmManager and shown in the notification anyway.
  Outside this module's boundary; accepted residual against a root/forensic adversary.

## Assumptions

- Android Keystore honestly protects the wrap key (TEE/StrongBox where available, else
  software). The code does **not** explicitly request StrongBox and does **not** verify the
  actual backing level — claims are "hardware where the platform provides it, software otherwise."
- The platform `SecureRandom` provides cryptographic entropy.
- The backup password is known only to the user and is not stored by the app.

## Untrusted-input boundary

These parse attacker-controllable bytes and must **fail closed** — return `null` / a controlled
error, and never crash, hang, over-allocate, or yield garbage as a successful decryption:

- `BackupCrypto.decrypt` — backup file. The KDF parameters live in an **unauthenticated** header
  and are range-clamped (≤ 128 MiB / ≤ 10 / ≤ 4) **before** Argon2 runs (DoS bound).
- `AeadBlob.open` — self-describing AES-GCM blob.

App-side importers (`.enex` / `.ics` / `.csv` / `.md`) and backup-JSON deserialization live in
the **private app module**, not in `:crypto`.

## Cryptographic parameters

- AES-256-GCM, 96-bit nonce, 128-bit tag (authenticated encryption only).
- Master secret: 256-bit `SecureRandom`, Keystore-wrapped.
- HKDF-SHA256 subkeys with domain labels (`db`, `audio`).
- Backup KDF: Argon2id, m = 64 MiB, t = 3, p = 1 (header-stored, clamped before use).
- PIN hash: Argon2id, m = 32 MiB, t = 2, p = 1, 16-byte salt, constant-time compare.

The detailed threat model (Russian) is in [THREAT_MODEL.md](THREAT_MODEL.md).
