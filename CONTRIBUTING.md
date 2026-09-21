# Contributing to GhostBytes

GhostBytes handles files, keys, passwords, and cryptographic operations. Keep
changes focused, reviewable, and free of sensitive data.

## Development Setup

GhostBytes requires Python 3.14 or newer and uses `uv` for dependency
management. From the repository root, run:

```bash
uv sync --group dev
```

When a package import or dependency is added, removed, or updated, update the
lockfile and environment in this order:

```bash
uv lock
uv sync --group dev
```

Run the application with:

```bash
uv run ghostbytes
```

## Checks

Before opening a pull request, run the relevant tests and static checks:

```bash
uv run pytest -s
uv run pylint src tools
uv run deptry .
```

Keep the existing style, avoid unrelated formatting changes, and add focused
tests for new behavior. Tests must be deterministic, isolated, and safe to run
on a development machine.

## Contributions

- Search existing issues and pull requests before starting substantial work.
- Use a focused branch and clear imperative commit subjects.
- Explain the problem, approach, tests, and compatibility implications in pull
  requests.
- Update documentation when commands, configuration, supported platforms,
  algorithms, file formats, or user-visible behavior changes.
- Do not commit virtual environments, caches, build output, private keys,
  passwords, test secrets, or user data.
- Report suspected vulnerabilities privately using [SECURITY.md](SECURITY.md),
  never in a public issue or pull request.

## Security And GUI Changes

For changes involving encryption, decryption, keys, passwords, random data,
hashing, file deletion, or dependencies:

- explain the security rationale and compatibility impact;
- use established library primitives;
- cover invalid, tampered, truncated, or incompatible input where applicable;
- never log passwords, private keys, plaintext, or complete ciphertext; and
- request review from a maintainer familiar with the affected security area.

The GUI was made by AI and must still be reviewed as production code. For GUI
changes, check keyboard access, focus order, readable errors, practical window
sizes, and every path that displays, accepts, stores, deletes, or transforms
sensitive data. Test the behavior behind the interface, not only its appearance.

By contributing, you agree to follow the project's applicable licenses and
community standards. Contributions are submitted under the [MIT License](LICENSE).
