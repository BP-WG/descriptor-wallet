# Bitcoin protocol wallet-level libraries

![Build](https://github.com/BP-WG/bp-wallet/workflows/Build/badge.svg)
![Tests](https://github.com/BP-WG/bp-wallet/workflows/Tests/badge.svg)
![Lints](https://github.com/BP-WG/bp-wallet/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/BP-WG/bp-wallet/branch/master/graph/badge.svg)](https://codecov.io/gh/BP-WG/descriptor-wallet)

[![crates.io](https://img.shields.io/crates/v/bp-wallet)](https://crates.io/crates/descriptor-wallet)
[![Docs](https://docs.rs/bp-wallet/badge.svg)](https://docs.rs/descriptor-wallet)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Apache2 licensed](https://img.shields.io/badge/license-Apache%202-blue)](./LICENSE)

Library for building bitcoin and LNP/BP wallets. Everything a modern cold 
bitcoin wallet needs, but which is not (yet) a part of 
[rust-bitcoin](https://crates.io/bitcoin) library.

Library provides

- efficient manipulations with BIP-32 derivation paths, separating derivations
  requiring private key access from those, which will always operate without;
- PSBT constructor using input descriptors, which allow to specify custom
  information about RBFs, previous public key P2C tweaks and custom hash types
  on a per-input basis;
- PSBT signer, supporting RBFs, relative and absolute timelocks, all sighash
  types, complex scripts, including witness- and taproot-based;
- lexicographic ordering of transaction & PSBT inputs & oututs;
- PSBT utility functions (retrieving previous output, computing fee);
- transaction resolver API on top of Electrum Server API for convenience
  computation of already-mined transaction fees etc;
- support for SLIP-32/132 extended pubkey types (`ypub`, `zprv` etc).
