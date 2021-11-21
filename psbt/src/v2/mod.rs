// Descriptor wallet library extending bitcoin & miniscript functionality
// by LNP/BP Association (https://lnp-bp.org)
// Written in 2020-2021 by
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

use bitcoin::util::bip32::{ExtendedPubKey, KeySource};
use bitcoin::Transaction;

use crate::raw;

pub struct PsbtV2 {
    pub tx_version: u32,

    pub fallback_locktime: Option<u32>,

    pub tx_modifiable: ModifyMode,

    /// A global map from extended public keys to the used key fingerprint and
    /// derivation path as defined by BIP 32
    pub xpub: BTreeMap<ExtendedPubKey, KeySource>,

    /// Global proprietary key-value pairs.
    #[cfg_attr(
        feature = "serde",
        serde(with = "::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,

    /// Unknown global key-value pairs.
    #[cfg_attr(
        feature = "serde",
        serde(with = "::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,

    pub inputs: Vec<()>,
    pub outputs: Vec<()>,
}

impl Default for PsbtV2 {
    #[inline]
    fn default() -> Self {
        PsbtV2 {
            tx_version: 2,
            fallback_locktime: None,
            tx_modifiable: ModifyMode::All,
            xpub: Default::default(),
            proprietary: Default::default(),
            unknown: Default::default(),
            inputs: vec![],
            outputs: vec![],
        }
    }
}

impl PsbtV2 {
    /// Used by creator. Sets [`PsbtV2::tx_modifiable`] to [`ModifyMode::All`]
    /// or [`ModifyMode::AllSighashSingle`] depending on whether
    /// `sighash_snigle` is set. Allows to set `PSBT_GLOBAL_PREFERRED_LOCKTIME`.
    pub fn new(sighash_single: bool, fallback_locktime: Option<u32>) -> Self {
        let tx_modifiable = if sighash_single {
            ModifyMode::AllSighashSingle
        } else {
            ModifyMode::All
        };
        PsbtV2 {
            fallback_locktime,
            tx_modifiable,
            ..PsbtV2::default()
        }
    }

    pub fn with(_tx: Transaction, _mode: ModifyMode) -> Self { todo!() }
}

pub enum ModifyMode {
    None = 0b000,
    Inputs = 0b001,
    Outputs = 0b010,
    All = 0b011,
    SighashSingle = 0b100,
    InputsSighashSingle = 0b101,
    OutputsSighashSingle = 0b110,
    AllSighashSingle = 0b111,
}

impl ModifyMode {
    pub fn is_inputs_modifiable(self) -> bool { todo!() }
}
