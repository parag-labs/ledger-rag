# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses [semantic versioning](https://semver.org/).

## [Unreleased]

### Changed

- Toolchains: Python 3.14, Go 1.27, Java 25, Node.js 26 LTS, Rust edition 2024 (rust-version 1.99); .NET stays on 10 (LTS), now pinned via `global.json`. CI actions bumped to their latest majors.
- Libraries: TypeScript 7, Vitest 5, Jackson 3, JUnit 6, BouncyCastle 1.86 (Java) / 2.7.0 (.NET), `sha2` 0.11, `ed25519-dalek` 3, `getrandom` 0.4; raised Python dependency floors (ruff 0.17.3).

## [0.1.0] - 2026-08-09

First public release. verifiable RAG with a tamper-evident Merkle ledger and standalone C#/Java verifiers.

[0.1.0]: https://github.com/parag-labs/ledger-rag/releases/tag/v0.1.0
