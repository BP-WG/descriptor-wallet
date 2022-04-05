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
use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use amplify::hex::{FromHex, ToHex};
use bitcoin::util::bip32::{ExtendedPubKey, KeySource};
use bitcoin::{consensus, Transaction};
#[cfg(feature = "serde")]
use serde_with::{hex::Hex, As, Same};

use crate::serialize::{Deserialize, Serialize};
use crate::v0::PsbtV0;
use crate::{raw, Error, Input, Output, PsbtVersion, TxError};

// TODO: Do manual serde and strict encoding implementation to check the
//       deserialized values
#[derive(Clone, Eq, PartialEq, Debug, Default)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct Psbt {
    /// The version number of this PSBT. If omitted, the version number is 0.
    pub psbt_version: PsbtVersion,

    /// A global map from extended public keys to the used key fingerprint and
    /// derivation path as defined by BIP 32
    pub xpub: BTreeMap<ExtendedPubKey, KeySource>,

    /// Transaction version.
    pub tx_version: u32,

    // TODO: Do optional
    /// Fallback locktime (used if none of the inputs specifies their locktime).
    pub fallback_locktime: u32,

    /// The corresponding key-value map for each input.
    pub inputs: Vec<Input>,

    /// The corresponding key-value map for each output.
    pub outputs: Vec<Output>,

    /// Global proprietary key-value pairs.
    #[cfg_attr(feature = "serde", serde(with = "As::<BTreeMap<Same, Hex>>"))]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,

    /// Unknown global key-value pairs.
    #[cfg_attr(feature = "serde", serde(with = "As::<BTreeMap<Same, Hex>>"))]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}

impl Psbt {
    /// Checks that unsigned transaction does not have scriptSig's or witness
    /// data
    pub fn with(tx: Transaction, psbt_version: PsbtVersion) -> Result<Self, TxError> {
        let inputs = tx
            .input
            .into_iter()
            .enumerate()
            .map(|(index, txin)| Input::new(index, txin).map_err(TxError::from))
            .collect::<Result<_, TxError>>()?;
        let outputs = tx
            .output
            .into_iter()
            .enumerate()
            .map(|(index, txout)| Output::new(index, txout))
            .collect();

        let i32_version = tx.version;
        let tx_version = i32_version
            .try_into()
            .map_err(|_| TxError::InvalidTxVersion(i32_version))?;

        Ok(Psbt {
            psbt_version,
            xpub: Default::default(),
            tx_version,
            fallback_locktime: tx.lock_time,
            inputs,
            outputs,
            proprietary: Default::default(),
            unknown: Default::default(),
        })
    }

    /// Extract the Transaction from a PartiallySignedTransaction by filling in
    /// the available signature information in place.
    #[inline]
    pub fn extract_tx(self) -> Transaction {
        PsbtV0::from(self).extract_tx()
    }

    /// Combines this [`Psbt`] with `other` PSBT as described by BIP 174.
    ///
    /// In accordance with BIP 174 this function is commutative i.e.,
    /// `A.combine(B) == B.combine(A)`
    #[inline]
    pub fn combine(self, other: Self) -> Result<Self, Error> {
        let mut first = PsbtV0::from(self);
        first.combine(other.into())?;
        Ok(first.into())
    }
}

impl From<PsbtV0> for Psbt {
    fn from(v0: PsbtV0) -> Self {
        let tx = v0.unsigned_tx;

        let inputs = v0
            .inputs
            .into_iter()
            .zip(tx.input)
            .enumerate()
            .map(|(index, (input, txin))| Input::with(index, input, txin))
            .collect();

        let outputs = v0
            .outputs
            .into_iter()
            .zip(tx.output)
            .enumerate()
            .map(|(index, (output, txout))| Output::with(index, output, txout))
            .collect();

        let tx_version = u32::from_be_bytes(tx.version.to_be_bytes());

        Psbt {
            // We need to serialize back in the same version we deserialzied from
            psbt_version: PsbtVersion::V0,
            xpub: v0.xpub,
            tx_version,
            fallback_locktime: tx.lock_time,
            inputs,
            outputs,
            proprietary: v0.proprietary,
            unknown: v0.unknown,
        }
    }
}

impl From<Psbt> for PsbtV0 {
    fn from(psbt: Psbt) -> Self {
        let version = i32::from_be_bytes(psbt.tx_version.to_be_bytes());

        let lock_time = psbt
            .inputs
            .iter()
            .filter_map(Input::locktime)
            .max()
            .unwrap_or(psbt.fallback_locktime);

        let (v0_inputs, tx_inputs) = psbt.inputs.into_iter().map(Input::split).unzip();
        let (v0_outputs, tx_outputs) = psbt.outputs.into_iter().map(Output::split).unzip();

        let unsigned_tx = Transaction {
            version,
            lock_time,
            input: tx_inputs,
            output: tx_outputs,
        };

        PsbtV0 {
            unsigned_tx,
            version: PsbtVersion::V0 as u32,
            xpub: psbt.xpub,
            proprietary: psbt.proprietary,
            unknown: psbt.unknown,
            inputs: v0_inputs,
            outputs: v0_outputs,
        }
    }
}

// TODO: Implement own PSBT BIP174 serialization trait and its own custom error
//       type handling different PSBT versions.
impl Serialize for Psbt {
    fn serialize(&self) -> Vec<u8> {
        consensus::encode::serialize::<PsbtV0>(&self.clone().into())
    }
}

impl Deserialize for Psbt {
    fn deserialize(bytes: &[u8]) -> Result<Self, consensus::encode::Error> {
        consensus::deserialize::<PsbtV0>(bytes).map(Psbt::from)
    }
}

impl Display for Psbt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.serialize().to_hex())
    }
}

impl FromStr for Psbt {
    type Err = consensus::encode::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Psbt::deserialize(
            &Vec::<u8>::from_hex(s).map_err(|_| Self::Err::ParseFailed("invalid hex encoding"))?,
        )
    }
}

#[cfg(test)]
mod test {
    use strict_encoding::StrictDecode;
    use strict_encoding_test::test_encoding_roundtrip;

    use super::*;

    #[test]
    fn psbt_bip174_serialization() {
        let hex = "\
            70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566\
            cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a91\
            4d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a914\
            3545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda50101000\
            00000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f\
            9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985fffff\
            fff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b4\
            0100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff020\
            0c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac\
            72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587024\
            7304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a\
            5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02\
            db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e\
            7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0\
            c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20\
            167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4\
            ea169393380734464f84f2ab300000000000000";

        let psbt = Psbt::from_str(hex).unwrap();
        let hex_prime = psbt.to_string();
        let psbt_prime = Psbt::deserialize(&Vec::from_hex(&hex_prime).unwrap()).unwrap();
        assert_eq!(psbt, psbt_prime);
        assert_eq!(hex, hex_prime);
    }

    #[test]
    fn psbt_strict_encoding() {
        let psbt_bytes = Vec::from_hex(
            "00000002000000b32e130001000000268171371edff285e937adeea4b37b78000c\
            0566cbb3ad64641713ca42171bf60000000001feffffff000001010000000001028\
            9a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100\
            000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa4\
            3a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017\
            160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000\
            000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c\
            00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202\
            712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220\
            018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012\
            103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105\
            02483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc30\
            9ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c868403\
            1c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea16939338\
            0734464f84f2ab30000000000000000000000000000000000000000000000000000\
            00000000000000000002000000d3dff50500000000190076a914d0c59903c5bac28\
            68760e90fd521a4665aa7652088ac000000000000000000000000010000e1f50500\
            0000001700a9143545e6e33b832c47050f24d3eeb93c9c03948bc78700000000000\
            000000000000000000000",
        )
        .unwrap();

        let psbt = Psbt::strict_deserialize(&psbt_bytes).unwrap();

        test_encoding_roundtrip(&psbt, &psbt_bytes).unwrap();
    }
}
