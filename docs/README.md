# GhostBytes Documentation

This folder contains the project reference material for the desktop encryption application. Use the project root [README](../README.md) for installation, high-level feature summaries, and security notes, and use these documents for deeper implementation and workflow guidance.

## Documentation index

- [Getting Started](getting-started.md) — first-run workflow, encryption, signing, key management, common problems, and next steps.
- [Configuration](configuration.md) — full reference for `CryptoConfig`, supported algorithms, salts, KDF settings, hash selection, and import/export behavior.
- [Cryptography](cryptography.md) — design overview of AES-GCM, RSA-OAEP, hybrid RSA, ML-KEM encryption, RSA-PSS, and ML-DSA signatures.
- [Architecture](architecture.md) — module boundaries, event flow, runtime structure, and extension points.

## Related project links

- [Project README](../README.md)
- [License](../LICENSE)
- [Security Policy](../SECURITY.md)
- [Contributing Guide](../CONTRIBUTING.md)

## Suggested reading order

1. [Getting Started](getting-started.md)
2. [Configuration](configuration.md)
3. [Cryptography](cryptography.md)
4. [Architecture](architecture.md)
5. [Project README](../README.md)

This docs directory is intended to support onboarding and deeper technical understanding without repeating the project-level overview in the root README.
