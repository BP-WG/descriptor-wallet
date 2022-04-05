// Descriptor wallet library extending bitcoin & miniscript functionality
// by LNP/BP Association (https://lnp-bp.org)
// Written in 2020-2022 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the Apache-2.0 License
// along with this software.
// If not, see <https://opensource.org/licenses/Apache-2.0>.

use std::collections::BTreeMap;

use bitcoin::psbt::TapTree;
use bitcoin::util::bip32::KeySource;
use bitcoin::util::taproot::TapLeafHash;
use bitcoin::{secp256k1, Script, XOnlyPublicKey};

use crate::raw;
use crate::v0::OutputV0;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Output {
    /// The redeem script for this output.
    pub redeem_script: Option<Script>,

    /// The witness script for this output.
    pub witness_script: Option<Script>,

    /// A map from public keys needed to spend this output to their
    /// corresponding master key fingerprints and derivation paths.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_as_seq"))]
    pub bip32_derivation: BTreeMap<secp256k1::PublicKey, KeySource>,

    /// The internal pubkey.
    pub tap_internal_key: Option<XOnlyPublicKey>,

    /// Taproot Output tree.
    pub tap_tree: Option<TapTree>,

    /// Map of tap root x only keys to origin info and leaf hashes contained in
    /// it.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_as_seq"))]
    pub tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,

    /// Proprietary key-value pairs for this output.
    #[cfg_attr(
        feature = "serde",
        serde(with = "::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,

    /// Unknown key-value pairs for this output.
    #[cfg_attr(
        feature = "serde",
        serde(with = "::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}
