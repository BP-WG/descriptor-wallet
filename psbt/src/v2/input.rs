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

use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d};
use bitcoin::psbt::PsbtSigHashType;
use bitcoin::util::bip32::KeySource;
use bitcoin::util::taproot::{ControlBlock, LeafVersion, TapBranchHash, TapLeafHash};
use bitcoin::{
    secp256k1, EcdsaSig, PublicKey, SchnorrSig, Script, Transaction, TxOut, Witness, XOnlyPublicKey,
};

use crate::raw;
use crate::v1::InputV1;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Input {
    /// The non-witness transaction this input spends from. Should only be
    /// `Some` for inputs which spend non-segwit outputs or if it is unknown
    /// whether an input spends a segwit output.
    pub non_witness_utxo: Option<Transaction>,

    /// The transaction output this input spends from. Should only be `Some` for
    /// inputs which spend segwit outputs, including P2SH embedded ones.
    pub witness_utxo: Option<TxOut>,

    /// A map from public keys to their corresponding signature as would be
    /// pushed to the stack from a scriptSig or witness for a non-taproot
    /// inputs.
    pub partial_sigs: BTreeMap<PublicKey, EcdsaSig>,

    /// The sighash type to be used for this input. Signatures for this input
    /// must use the sighash type.
    pub sighash_type: Option<PsbtSigHashType>,

    /// The redeem script for this input.
    pub redeem_script: Option<Script>,

    /// The witness script for this input.
    pub witness_script: Option<Script>,

    /// A map from public keys needed to sign this input to their corresponding
    /// master key fingerprints and derivation paths.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_as_seq"))]
    pub bip32_derivation: BTreeMap<secp256k1::PublicKey, KeySource>,

    /// The finalized, fully-constructed scriptSig with signatures and any other
    /// scripts necessary for this input to pass validation.
    pub final_script_sig: Option<Script>,

    /// The finalized, fully-constructed scriptWitness with signatures and any
    /// other scripts necessary for this input to pass validation.
    pub final_script_witness: Option<Witness>,

    /// TODO: Proof of reserves commitment

    /// RIPEMD160 hash to preimage map.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_byte_values"))]
    pub ripemd160_preimages: BTreeMap<ripemd160::Hash, Vec<u8>>,

    /// SHA256 hash to preimage map.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_byte_values"))]
    pub sha256_preimages: BTreeMap<sha256::Hash, Vec<u8>>,

    /// HSAH160 hash to preimage map.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_byte_values"))]
    pub hash160_preimages: BTreeMap<hash160::Hash, Vec<u8>>,

    /// HAS256 hash to preimage map.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_byte_values"))]
    pub hash256_preimages: BTreeMap<sha256d::Hash, Vec<u8>>,

    /// Serialized schnorr signature with sighash type for key spend.
    pub tap_key_sig: Option<SchnorrSig>,

    /// Map of <xonlypubkey>|<leafhash> with signature.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_as_seq"))]
    pub tap_script_sigs: BTreeMap<(XOnlyPublicKey, TapLeafHash), SchnorrSig>,

    /// Map of Control blocks to Script version pair.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_as_seq"))]
    pub tap_scripts: BTreeMap<ControlBlock, (Script, LeafVersion)>,

    /// Map of tap root x only keys to origin info and leaf hashes contained in
    /// it.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_as_seq"))]
    pub tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,

    /// Taproot Internal key.
    pub tap_internal_key: Option<XOnlyPublicKey>,

    /// Taproot Merkle root.
    pub tap_merkle_root: Option<TapBranchHash>,

    /// Proprietary key-value pairs for this input.
    #[cfg_attr(
        feature = "serde",
        serde(with = "::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,

    /// Unknown key-value pairs for this input.
    #[cfg_attr(
        feature = "serde",
        serde(with = "::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}
