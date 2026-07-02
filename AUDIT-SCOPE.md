# External Audit Scope — Arx Notes `:crypto`

Purpose: give an external reviewer (e.g. a Cure53 / Trail of Bits–style engagement) a ready
map so the audit can go straight to verification. This document does **not** claim any audit
was performed — see the honest status in [SECURITY.md](SECURITY.md).

## In scope

The `:crypto` Gradle module — Kotlin, Android library, `minSdk 26`, package
`app.arxnotes.core.crypto`. Single third-party dependency: **BouncyCastle** (Argon2id).

| File | Role |
|---|---|
| `src/main/.../MasterKeyManager.kt` | Root of trust: Keystore wrap, HKDF subkeys, device-locked & key-invalidation handling |
| `src/main/.../AeadBlob.kt` *(internal)* | AES-256-GCM self-describing blob |
| `src/main/.../Hkdf.kt` *(internal)* | HKDF-SHA256 |
| `src/main/.../AudioCrypto.kt` | Voice-note encryption (public API) |
| `src/main/.../BackupCrypto.kt` | Password backup files (public API) |
| `src/main/.../PinHasher.kt` | One-way PIN hash (public API) |
| `src/test/**`, `src/androidTest/**` | Test suite (KAT, fuzz, integrity, instrumented Keystore) |
| `build.gradle.kts`, `consumer-rules.pro` | Build & consumer ProGuard rules |

## Out of scope (private app module, mentioned where it consumes `:crypto`)

SQLCipher wiring (`AppDatabase`), voice-note storage/playback, PIN attempt-throttling,
backup JSON (de)serialization, `.enex/.ics/.csv/.md` importers, `FLAG_SECURE`, DI, AlarmManager.

## Reviewer checklist

### 1. Primitives
- [ ] AES-256-GCM everywhere; 128-bit tag; no ECB/CBC/unauthenticated mode (`AeadBlob.kt`, `BackupCrypto.kt`, `MasterKeyManager.kt`).
- [ ] 256-bit keys throughout.
- [ ] GCM nonce is provider-generated, never reused or zeroed (`AeadBlob.seal`); see `NonceUniquenessTest`.
- [ ] HKDF-SHA256 is RFC 5869-conformant — cross-check `KnownAnswerTest` (Test Cases 1–3).

### 2. KDF
- [ ] Argon2id v1.3 for backup (m = 64 MiB, t = 3, p = 1) and PIN (m = 32 MiB, t = 2, p = 1) — cross-check the RFC 9106 §5.3 vector and the parameter-recompute test (`KnownAnswerTest`, `PinHasherTest`).
- [ ] Backup header parameters clamped **before** Argon2 runs (`BackupCrypto.kt`, the `MAX_*` bounds); see `BackupIntegrityTest`.
- [ ] Judgement call: is the 128 MiB memory ceiling appropriate for low-RAM `minSdk 26` devices, or should it be tightened toward the 64 MiB write-default? (See item M6.)

### 3. Key management
- [ ] Master secret = 256-bit `SecureRandom`; only the wrapped blob touches disk; wrap key non-exportable (`MasterKeyManager.kt`).
- [ ] `setUnlockedDeviceRequired(true)` (API ≥ 28); locked device → `DeviceLockedException` (distinguished from corruption).
- [ ] Permanent key invalidation → `KeyInvalidatedException` (not "corrupt blob"); logic in `mapKeystoreInvalidation`. Note: the OS-side invalidation trigger is only manually testable.
- [ ] HKDF domain separation (db vs audio); master zeroized after derivation (`finally`).
- [ ] StrongBox is **not** requested and the backing level is **not** verified — claims are scoped accordingly.

### 4. Integrity / AEAD
- [ ] Decryption fails closed; no partial-plaintext release; `open`/`decrypt` return `null` on any tamper/truncation/wrong key/version — cross-check `AeadIntegrityTest`, `BackupIntegrityTest`.
- [ ] Versioned, self-describing formats; downgrade / format-confusion resistance.

### 5. Side channels
- [ ] PIN compare is constant-time (`MessageDigest.isEqual`); no early-exit comparator — guarded by `SecureConstructionGuardTest`.
- [ ] No decryption oracle: a single `null`, with no distinguishing exception or timing branch on secret data.
- [ ] Transient key/password buffers wiped in `finally` (RAM dump is out of scope per SECURITY.md) — guarded by `SecureConstructionGuardTest`.

### 6. Secret hygiene
- [ ] No hardcoded keys/salts/passwords/tokens in `src/main` — guarded by `SourceHygieneTest`; confirmed by a static-analysis pass (`:crypto:lint` clean).
- [ ] No sensitive logging; no personal paths/identifiers.
- [ ] Recommended before making the git history public: a history secret scan (e.g. `gitleaks`).

### 7. Untrusted input / fuzzing
- [ ] `BackupCrypto.decrypt` and `AeadBlob.open` never crash, hang, over-allocate, or yield garbage on arbitrary bytes — cross-check the 5000-input fuzz in `BackupIntegrityTest` and the `AeadBlob` fuzz.

### 8. Mobile surface (where the app consumes `:crypto`)
- [ ] No `INTERNET` permission; `allowBackup=false`; `FLAG_SECURE` on secret-bearing screens.
- [ ] Accepted residual: reminder text in an AlarmManager `PendingIntent` (cannot be narrowed without breaking locked-device reminders — see SECURITY.md).

## Build & test

```bash
./gradlew :crypto:test                  # unit (JVM)
./gradlew :crypto:connectedAndroidTest  # instrumented (device/emulator, screen unlocked)
./gradlew :crypto:lintDebug             # Android lint
```

## Known open items (non-blocking, owner-tracked)

- **M6 (resolved)** — backup Argon2 header parameters are now clamped to memory ≤ 128 MiB, iterations ≤ 10, parallelism ≤ 4, enforced **before** Argon2 runs (`BackupCrypto.kt`). Residual product judgement: 128 MiB is still attacker-selectable from the header; tightening toward the 64 MiB write-default would further bound memory pressure on low-RAM devices.
- **detekt/ktlint** — not yet wired into CI; recommended for a public module.
- **CI** — a GitHub Actions workflow (`.github/workflows/ci.yml`) runs `:crypto:test`; live status is badged in the README.
