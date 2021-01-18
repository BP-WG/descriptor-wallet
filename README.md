# Descriptor wallet library

![Build](https://github.com/LNP-BP/descriptor-wallet/workflows/Build/badge.svg)
![Tests](https://github.com/LNP-BP/descriptor-wallet/workflows/Tests/badge.svg)
![Lints](https://github.com/LNP-BP/descriptor-wallet/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/LNP-BP/descriptor-wallet/branch/master/graph/badge.svg)](https://codecov.io/gh/LNP-BP/descriptor-wallet)

[![crates.io](https://meritbadge.herokuapp.com/descriptor-wallet)](https://crates.io/crates/descriptor-wallet)
[![Docs](https://docs.rs/descriptor-wallet/badge.svg)](https://docs.rs/descriptor-wallet)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![MIT licensed](https://img.shields.io/github/license/LNP-BP/descriptor-wallet)](./LICENSE)

Library for building descriptor-based bitcoin wallets. Previously was a part of
[LNP/BP Core Library](https://github.com/LNP-BP/rust-lnpbp).

Components:
- More efficient manipulations with BIP-32 derivation paths
- Universal miniscript/classical bitcoin descriptors
- Script templates allowing embedding extended pubkeys into bitcoin script 
  assembly
- Lexicographic ordering of transaction & PSBT inputs & oututs
- Script type system
- Helper types for working with hash-lock contracts
- PSBT utility functions (retrieving previous output, computing fee)

Includes separate crate for SLIP-132 functionality in [`/slip132`](./slip132)
subdirectory.
