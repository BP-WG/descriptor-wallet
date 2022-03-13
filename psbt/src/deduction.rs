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

use bitcoin::util::address::WitnessVersion;
use bitcoin::TxIn;
use bitcoin_scripts::PubkeyScript;
use descriptors::CompositeDescrType;

use crate::{Input, InputPrevout};

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

/// Extension trait for deducing information about spendings from PSBT input
pub trait InputDeduce {
    /// Deduction of a descriptor type from a `scriptPubkey` data and data
    /// inside  redeem script and witness scripts.
    ///
    /// # Errors
    ///
    /// The function may [`DeductionError`]
    ///
    /// # Panics
    ///
    /// Panics if PSBT integrity is broken and current input does not have an
    /// associated previous output data or these data are incorrect.
    fn composite_descr_type(&self) -> Result<CompositeDescrType, DeductionError>;
}

impl InputDeduce for (&Input, &TxIn) {
    fn composite_descr_type(&self) -> Result<CompositeDescrType, DeductionError> {
        let spk = &self
            .input_prevout()
            .expect("PSBT integrity is broken")
            .script_pubkey;
        let spk = PubkeyScript::from(spk.clone());
        match (spk, spk.witness_version()) {
            (spk, _) if spk.is_p2pk() => Ok(CompositeDescrType::Pk),
            (spk, _) if spk.is_p2pkh() => Ok(CompositeDescrType::Pkh),
            (spk, _) if spk.is_v0_p2wpkh() => Ok(CompositeDescrType::Wpkh),
            (spk, _) if spk.is_v0_p2wsh() => Ok(CompositeDescrType::Wsh),
            (spk, _) if spk.is_v1_p2tr() => Ok(CompositeDescrType::Tr),
            (spk, _) if spk.is_p2sh() => {
                let redeem_script = if let Some(redeem_script) = &self.0.redeem_script {
                    redeem_script
                } else {
                    return Err(DeductionError::P2shWithoutRedeemScript);
                };
                if self.0.witness_script.is_some() {
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
