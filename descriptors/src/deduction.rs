// Wallet-level libraries for bitcoin protocol by LNP/BP Association
//
// Written in 2020-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// This software is distributed without any warranty.
//
// You should have received a copy of the Apache-2.0 License
// along with this software.
// If not, see <https://opensource.org/licenses/Apache-2.0>.

use bitcoin::address::WitnessVersion;

use crate::CompositeDescrType;

/// Errors that happens during deduction process
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error
)]
#[display(doc_comments)]
pub enum DeductionError {
    /// input spends non-taproot witness version 1
    NonTaprootV1,

    /// input spends future witness version {0}
    UnsupportedWitnessVersion(WitnessVersion),

    /// input spends P2SH output, but no `redeedScript` is present in the PSBT
    /// input data
    P2shWithoutRedeemScript,

    /// redeem script is invalid in context of nested (legacy) P2W*-in-P2SH
    /// spending
    InvalidRedeemScript,
}

impl CompositeDescrType {
    /// Deduction of a descriptor type from a `scriptPubkey` data and data
    /// inside redeem script and witness scripts.
    ///
    /// # Errors
    ///
    /// The function may [`DeductionError`]
    ///
    /// # Panics
    ///
    /// Panics if PSBT integrity is broken and current input does not have an
    /// associated previous output data or these data are incorrect.
    pub fn deduce(
        spk: &PubkeyScript,
        redeem_script: Option<&RedeemScript>,
        witness_script_known: bool,
    ) -> Result<Self, DeductionError> {
        let witness_version = spk.witness_version();
        match (spk, witness_version) {
            (spk, _) if spk.is_p2pk() => Ok(CompositeDescrType::Pk),
            (spk, _) if spk.is_p2pkh() => Ok(CompositeDescrType::Pkh),
            (spk, _) if spk.is_v0_p2wpkh() => Ok(CompositeDescrType::Wpkh),
            (spk, _) if spk.is_v0_p2wsh() => Ok(CompositeDescrType::Wsh),
            (spk, _) if spk.is_v1_p2tr() => Ok(CompositeDescrType::Tr),
            (spk, _) if spk.is_p2sh() => {
                let redeem_script = if let Some(redeem_script) = redeem_script {
                    redeem_script
                } else {
                    return Err(DeductionError::P2shWithoutRedeemScript);
                };
                if witness_script_known {
                    if redeem_script.is_v0_p2wpkh() {
                        Ok(CompositeDescrType::ShWpkh)
                    } else if redeem_script.is_v0_p2wsh() {
                        Ok(CompositeDescrType::ShWsh)
                    } else {
                        Err(DeductionError::InvalidRedeemScript)
                    }
                } else {
                    Ok(CompositeDescrType::Sh)
                }
            }
            (_, Some(WitnessVersion::V1)) => Err(DeductionError::NonTaprootV1),
            (_, Some(version)) => Err(DeductionError::UnsupportedWitnessVersion(version)),
            (_, None) => Ok(CompositeDescrType::Bare),
        }
    }
}
