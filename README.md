# omyra-core

Clean-room cryptography (SHA-256/512, ChaCha20-Poly1305, HKDF, Ed25519) plus shared types. Each primitive is checked against its NIST/RFC test vector.

Part of the **[Omyra](https://github.com/omyraxyz)** open-source utility stack — the
Private Autonomous AI Protocol (shared crypto + types).

Website: https://omyra.xyz · Docs: https://docs.omyra.xyz · Whitepaper: https://omyra.xyz/whitepaper

## Status

Reference implementation (pre-audit), MIT-licensed. Run `cargo test` for the suite.
The cryptography is real and test-vector-validated; hardware/ZK integrations sit
behind clean seams swapped in for production. We state shipped vs target plainly.
