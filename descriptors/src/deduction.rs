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

use std::convert::TryFrom;

use amplify::Wrapper;
use bitcoin_scripts::{Category, PubkeyScript, WitnessVersion};

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
    ) -> Result<Category, DeductionError>;
}

impl Deduce for Category {
    fn deduce(
        pubkey_script: &PubkeyScript,
        has_witness: Option<bool>,
    ) -> Result<Category, DeductionError> {
        match pubkey_script.as_inner() {
            p if p.is_v0_p2wpkh() || p.is_v0_p2wsh() => Ok(Category::SegWit),
            p if p.is_witness_program() => {
                const ERR: &str = "bitcoin::Script::is_witness_program is broken";
                match WitnessVersion::try_from(
                    p.instructions_minimal().next().expect(ERR).expect(ERR),
                )
                .expect(ERR)
                {
                    WitnessVersion::V0 => unreachable!(),
                    WitnessVersion::V1 => Ok(Category::Taproot),
                    ver => Err(DeductionError::UnsupportedWitnessVersion(ver)),
                }
            }
            p if p.is_p2pkh() => Ok(Category::Hashed),
            p if p.is_p2sh() => match has_witness {
                None => Err(DeductionError::IncompleteInformation),
                Some(true) => Ok(Category::Nested),
                Some(false) => Ok(Category::Hashed),
            },
            _ => Ok(Category::Bare),
        }
    }
}

// TODO #18: Implement deduction for other script types
