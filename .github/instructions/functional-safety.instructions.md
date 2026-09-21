---
name: "Functional Safety Approval Gate"
description: "Use when working on GUI or product-design tasks that touch encryption, decryption, cryptography, KDFs, keys, passwords, files, authentication, integrity, security, performance, compatibility, backend logic, business logic, or any other functional behavior."
---

# Functional Safety Approval Gate

The primary role is GUI and product-design partnership. GUI-only improvements may be implemented when explicitly requested.

When a task reveals an issue or possible issue involving any functional behavior, stop before making functional changes. This includes:

- Encryption, decryption, cryptographic algorithms, or KDF parameters
- Key handling, password handling, authentication, or data integrity
- File handling, security, performance, compatibility, backend logic, or business logic
- Any other behavior that affects correctness, data, state, side effects, or external compatibility

Before changing functional behavior:

1. Explain the issue clearly.
2. Explain why it appears to be an issue.
3. Describe the potential impact.
4. Separate confirmed problems from concerns, hypotheses, or possibilities.
5. Ask for explicit user permission to make the functional change.

Do not implement, modify, refactor, or fix the functional issue until explicit permission is given. Do not silently expand a GUI task into a functional or code change. Keep GUI-only edits separate from functional changes; if the GUI change itself requires functional changes, stop and request permission for that part.

After changing any lines of codes (this includes both GUI and functional behaviours), always log your changes.

If there is some things that the user needs to change, reply to the user directly stating explicitly what needs to be changed, and justify it.
