# PSBT implementation

Implements both v0 (BIP-174) and v2 (BIP-370) versions of PSBT specification.

Based on [bitcoin](https://crates.io/crate/bitcoin) PSBT implementation, but
wraps it into new type system supporting v2 features and providing convenient
functions to iterate over sets of transaction inputs/outputs and corresponding
PSBT key maps.
