# Contributing to Arx Notes `:crypto`

Thanks for your interest. This module is the open cryptographic core of the Arx Notes
app, published on its own for independent review and reuse.

## Ground rules

- **Security first.** This is cryptographic code — prefer clarity and standard, reviewed
  constructions over cleverness. Changes to key handling, KDFs, or AEAD must explain the
  reasoning and come with tests.
- **No new runtime dependencies** without discussion. The only third-party runtime
  dependency is BouncyCastle (Argon2id). No networking, no Google/Firebase, no analytics.
- **Reproducible over stored.** Test results are produced by running the suite, not
  committed as files (`build/` is gitignored).

## Build & test

Prerequisites: **JDK 17** and the **Android SDK** (set `sdk.dir` in `local.properties`
or `ANDROID_HOME`).

```bash
./gradlew :crypto:testDebugUnitTest      # unit tests (JVM, no device)
./gradlew :crypto:connectedAndroidTest   # instrumented (device/emulator, screen unlocked)
./gradlew :crypto:lintDebug              # Android lint
```

The unit suite must pass before a PR is merged — CI runs it automatically on every push
and pull request.

## Coding conventions

- Kotlin, official code style (`kotlin.code.style=official`).
- Keep the public API small and documented; internal helpers stay `internal`.
- Every source file carries the Apache-2.0 header (copy it from an existing file).
- No secrets, personal data, or local machine paths in `src/main` — enforced by
  `SourceHygieneTest`.

## Pull requests

1. Fork and branch from `main`.
2. Add or adjust tests for any behavior change.
3. Run `./gradlew :crypto:testDebugUnitTest` locally.
4. Open a PR describing the change and its security rationale.

## Reporting security issues

**Do not** open a public issue for vulnerabilities. See
[SECURITY.md](https://github.com/ArxSecretorum/arxnotes-crypto/blob/main/SECURITY.md)
for private reporting.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
