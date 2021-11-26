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

use amplify::Wrapper;
use bitcoin::util::address;
use bitcoin::util::address::WitnessVersion;
use bitcoin_scripts::{ConvertInfo, PubkeyScript};

/// Errors that happens during [`Category::deduce`] process
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error
)]
#[display(doc_comments)]
pub enum DeductionError {
    /// For P2SH scripts we need to know whether it is created for the
    /// witness-containing spending transaction input, i.e. whether its redeem
    /// script will have a witness structure, or not. If this information was
    /// not provided, this error is returned.
    IncompleteInformation,

    /// Non-taproot witness version 1
    NonTaprootV1,

    /// Here we support only version 0 and 1 of the witness, otherwise this
    /// error is returned
    UnsupportedWitnessVersion(WitnessVersion),
}

pub trait Deduce {
    /// Deduction of a descriptor from a `scriptPubkey` data and,
    /// optionally, information about the presence of the witness for P2SH
    /// `scriptPubkey`'s.
    ///
    /// # Arguments
    ///
    /// * `pubkey_script` - script from transaction output `scriptPubkey`
    /// * `has_witness` - an optional `bool` with the following meaning:
    ///     - `None`: witness presence must be determined from the
    ///       `pubkey_script` value; don't use it for P2SH `scriptPubkey`s,
    ///       otherwise the method will return
    ///       [`DeductionError::IncompleteInformation`] error.
    ///     - `Some(true)`: presence of a witness structure will be required in
    ///       transaction input to spend the given `pubkey_script`, i.e. it was
    ///       composed with P2SH-P2W*H scheme
    ///     - `Some(false)`: if `scriptPubkey` is P2SH, it is a "normal" P2SH
    ///       and was not created with P2SH-P2W*H scheme. The spending
    ///       transaction input would not have `witness` structure.
    ///
    /// # Errors
    ///
    /// The function may [DeductionError] in the following cases
    ///
    /// * `IncompleteInformation`: the provided pubkey script (`pubkey_script`
    ///   argument) is P2SH script, and `has_witness` argument was set to `None`
    ///   (see explanation about the argument usage above).
    /// * `UnsupportedWitnessVersion(WitnessVersion)`: the provided pubkey
    ///   script has a witness version above 1.
    fn deduce(
        pubkey_script: &PubkeyScript,
        has_witness: Option<bool>,
    ) -> Result<ConvertInfo, DeductionError>;
}

impl Deduce for ConvertInfo {
    fn deduce(
        pubkey_script: &PubkeyScript,
        has_witness: Option<bool>,
    ) -> Result<ConvertInfo, DeductionError> {
        match address::Payload::from_script(pubkey_script.as_inner()) {
            None => Ok(ConvertInfo::Bare),
            Some(address::Payload::ScriptHash(_)) if has_witness == Some(true) => {
                Ok(ConvertInfo::NestedV0)
            }
            Some(address::Payload::ScriptHash(_)) if has_witness == None => {
                Err(DeductionError::IncompleteInformation)
            }
            Some(address::Payload::PubkeyHash(_) | address::Payload::ScriptHash(_)) => {
                Ok(ConvertInfo::Hashed)
            }
            Some(address::Payload::WitnessProgram {
                version: WitnessVersion::V0,
                ..
            }) => Ok(ConvertInfo::SegWitV0),
            Some(address::Payload::WitnessProgram {
                version: WitnessVersion::V1,
                ..
            }) => Ok(ConvertInfo::Taproot),
            Some(address::Payload::WitnessProgram { version, .. }) => {
                Err(DeductionError::UnsupportedWitnessVersion(version))
            }
        }
    }
}

// TODO #18: Implement deduction for other script types
