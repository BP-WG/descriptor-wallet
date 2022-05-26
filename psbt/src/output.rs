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
use bitcoin::{secp256k1, Script, TxOut, XOnlyPublicKey};
#[cfg(feature = "serde")]
use serde_with::{hex::Hex, As, Same};

use crate::raw;
use crate::v0::OutputV0;

// TODO: Do manual serde implementation to check the deserialized values
#[derive(Clone, Eq, PartialEq, Debug, Default)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct Output {
    /// The index of this output. Used in error reporting.
    pub(crate) index: usize,

    /// The output's amount in satoshis.
    pub amount: u64,

    /// The script for this output, also known as the scriptPubKey.
    pub script: Script,

    /// The redeem script for this output.
    pub redeem_script: Option<Script>,

    /// The witness script for this output.
    pub witness_script: Option<Script>,

    /// A map from public keys needed to spend this output to their
    /// corresponding master key fingerprints and derivation paths.
    #[cfg_attr(feature = "serde", serde(with = "As::<BTreeMap<Same, Same>>"))]
    pub bip32_derivation: BTreeMap<secp256k1::PublicKey, KeySource>,

    /// The internal pubkey.
    pub tap_internal_key: Option<XOnlyPublicKey>,

    /// Taproot Output tree.
    pub tap_tree: Option<TapTree>,

    /// Map of tap root x only keys to origin info and leaf hashes contained in
    /// it.
    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<BTreeMap<Same, (Vec<Same>, Same)>>")
    )]
    pub tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,

    /// Proprietary key-value pairs for this output.
    #[cfg_attr(feature = "serde", serde(with = "As::<BTreeMap<Same, Hex>>"))]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,

    /// Unknown key-value pairs for this output.
    #[cfg_attr(feature = "serde", serde(with = "As::<BTreeMap<Same, Hex>>"))]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}

impl Output {
    pub fn new(index: usize, txout: TxOut) -> Self {
        Output {
            index,
            amount: txout.value,
            script: txout.script_pubkey,
            ..Output::default()
        }
    }

    pub fn with(index: usize, v0: OutputV0, txout: TxOut) -> Self {
        Output {
            index,
            amount: txout.value,
            script: txout.script_pubkey,
            redeem_script: v0.redeem_script,
            witness_script: v0.witness_script,
            bip32_derivation: v0.bip32_derivation,
            tap_internal_key: v0.tap_internal_key,
            tap_tree: v0.tap_tree,
            tap_key_origins: v0.tap_key_origins,
            proprietary: v0.proprietary,
            unknown: v0.unknown,
        }
    }

    #[inline]
    pub fn index(&self) -> usize { self.index }

    pub fn split(self) -> (OutputV0, TxOut) {
        (
            OutputV0 {
                redeem_script: self.redeem_script,
                witness_script: self.witness_script,
                bip32_derivation: self.bip32_derivation,
                tap_internal_key: self.tap_internal_key,
                tap_tree: self.tap_tree,
                tap_key_origins: self.tap_key_origins,
                proprietary: self.proprietary,
                unknown: self.unknown,
            },
            TxOut {
                value: self.amount,
                script_pubkey: self.script,
            },
        )
    }
}

impl From<Output> for OutputV0 {
    fn from(output: Output) -> Self {
        OutputV0 {
            redeem_script: output.redeem_script,
            witness_script: output.witness_script,
            bip32_derivation: output.bip32_derivation,
            tap_internal_key: output.tap_internal_key,
            tap_tree: output.tap_tree,
            tap_key_origins: output.tap_key_origins,
            proprietary: output.proprietary,
            unknown: output.unknown,
        }
    }
}
