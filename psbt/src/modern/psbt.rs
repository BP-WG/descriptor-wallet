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

use bitcoin::util::bip32::{ExtendedPubKey, KeySource};
use bitcoin::Transaction;

use crate::v0::PsbtV0;
use crate::{raw, Input, Output, PsbtVersion};

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Psbt {
    /// The version number of this PSBT. If omitted, the version number is 0.
    pub psbt_version: PsbtVersion,

    /// A global map from extended public keys to the used key fingerprint and
    /// derivation path as defined by BIP 32
    pub xpub: BTreeMap<ExtendedPubKey, KeySource>,

    /// Transaction version.
    pub tx_version: u32,

    /// Fallback locktime (used if none of the inputs specifies their locktime).
    pub fallback_locktime: u32,

    /// The corresponding key-value map for each input.
    pub inputs: Vec<Input>,

    /// The corresponding key-value map for each output.
    pub outputs: Vec<Output>,

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
}

impl From<PsbtV1> for Psbt {
    fn from(v1: PsbtV1) -> Self {
        let tx = v1.unsigned_tx;

        let inputs = v1
            .inputs
            .into_iter()
            .zip(tx.input)
            .map(|(input, txin)| Input::with(input, txin))
            .collect();

        let outputs = v1
            .inputs
            .into_iter()
            .zip(tx.output)
            .map(|(output, txout)| Output::with(output, txout))
            .collect();

        let tx_version = u32::from_be_bytes(tx.version.to_be_bytes());

        Psbt {
            // We need to serialize back in the same version we deserialzied from
            psbt_version: PsbtVersion::V0,
            xpub: v1.xpub,
            tx_version,
            fallback_locktime: tx.lock_time,
            inputs,
            outputs,
            proprietary: v1.proprietary,
            unknown: v1.unknown,
        }
    }
}

impl From<Psbt> for PsbtV1 {
    fn from(v2: Psbt) -> Self {
        let version = i32::from_be_bytes(v2.tx_version.to_be_bytes());

        let lock_time = v2
            .inputs
            .iter()
            .filter_map(Input::locktime)
            .max()
            .unwrap_or(v2.fallback_locktime);

        let (v0_inputs, tx_inputs) = v2.inputs.into_iter().map(Input::split).collect();
        let (v0_outputs, tx_outputs) = v2.outputs.into_iter().map(Output::split).collect();

        let unsigned_tx = Transaction {
            version,
            lock_time,
            input: tx_inputs,
            output: tx_outputs,
        };

        PsbtV1 {
            unsigned_tx,
            version: PsbtVersion::V0 as u32,
            xpub: v2.xpub,
            proprietary: v2.proprietary,
            unknown: v2.unknown,
            inputs: v0_inputs,
            outputs: v0_outputs,
        }
    }
}
