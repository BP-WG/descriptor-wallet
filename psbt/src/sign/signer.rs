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

//! Functions, errors and traits specific for PSBT signer role.

use core::ops::Deref;

use amplify::Wrapper;
use bitcoin::secp256k1::{self, Signing, Verification};
use bitcoin::util::bip143::SigHashCache;
use bitcoin::{PublicKey, Script, SigHashType as EcdsaSigHashType, Transaction, TxIn};
use bitcoin_scripts::{PubkeyScript, WitnessVersion};
use descriptors::{self, CompositeDescrType};
use miniscript::ToPublicKey;

use super::SecretProvider;
use crate::deduction::InputDeduce;
use crate::util::InputPrevout;
use crate::{DeductionError, Input, InputMatchError, InputP2cTweak, Psbt};

/// Errors happening during whole PSBT signing process
#[derive(Debug, Display, Error)]
#[display("failed to sign input #{input_index} because {error}")]
pub struct SignError {
    /// Signing error originating from a specific transaction input
    pub error: SignInputError,
    /// Index of the transaction input that has generated a error
    pub input_index: usize,
}

/// Errors happening during PSBT input signing process
#[derive(Debug, Display, From)]
#[display(doc_comments)]
pub enum SignInputError {
    /// public key {provided} provided with PSBT input does not match public
    /// key {derived} derived from the supplied private key using
    /// derivation path from that input
    PubkeyMismatch {
        provided: PublicKey,
        derived: PublicKey,
    },

    /// spent transaction does not match input prevout reference
    #[from]
    Match(InputMatchError),

    /// unable to sign future witness version {0} in output
    FutureWitness(WitnessVersion),

    /// unable to sign non-taproot witness version v1 output
    NonTaprootV1,

    /// no redeem or witness script specified for input
    NoPrevoutScript,

    /// input spending nested witness output does not contain redeem script
    /// source
    NoRedeemScript,

    /// redeem script is invalid in context of nested (legacy) P2W*-in-P2SH
    /// spending
    InvalidRedeemScript,

    /// transaction input is a non-witness input, but full spent
    /// transaction is not provided in the `non_witness_utxo` PSBT field.
    LegacySpentTransactionMissed,

    /// unable to derive private key with a given derivation path: elliptic
    /// curve prime field order (`p`) overflow or derivation resulting at the
    /// point-at-infinity.
    SecpPrivkeyDerivation,

    /// `scriptPubkey` from previous output does not match witness or redeem
    /// script from the same input supplied in PSBT
    ScriptPubkeyMismatch,

    /// error applying pay-to-contract public key tweak
    P2cTweak,

    /// rrror applying tweak matching public key {0}: the tweak
    /// value is either a modulo-negation of the original private key, or
    /// it leads to elliptic curve prime field order (`p`) overflow
    TweakFailure(secp256k1::PublicKey),

    /// miniscript parse error
    #[from]
    Miniscript(miniscript::Error),
}

impl std::error::Error for SignInputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SignInputError::FutureWitness(_) => None,
            SignInputError::NoPrevoutScript => None,
            SignInputError::NoRedeemScript => None,
            SignInputError::LegacySpentTransactionMissed => None,
            SignInputError::SecpPrivkeyDerivation => None,
            SignInputError::ScriptPubkeyMismatch => None,
            SignInputError::P2cTweak => None,
            SignInputError::TweakFailure(_) => None,
            SignInputError::NonTaprootV1 => None,
            SignInputError::Miniscript(err) => Some(err),
            SignInputError::PubkeyMismatch { .. } => None,
            SignInputError::Match(err) => Some(err),
            SignInputError::InvalidRedeemScript => None,
        }
    }
}

impl From<DeductionError> for SignInputError {
    fn from(err: DeductionError) -> Self {
        match err {
            DeductionError::NonTaprootV1 => SignInputError::NonTaprootV1,
            DeductionError::UnsupportedWitnessVersion(version) => {
                SignInputError::FutureWitness(version)
            }
            DeductionError::P2shWithoutRedeemScript => SignInputError::NoRedeemScript,
            DeductionError::InvalidRedeemScript => SignInputError::InvalidRedeemScript,
        }
    }
}

impl SignError {
    #[inline]
    pub fn with_input_no(error: SignInputError, input_index: usize) -> SignError {
        SignError { error, input_index }
    }
}

/// Extension trait for signing complete PSBT
pub trait SignAll {
    /// Signs all PSBT inputs using all known keys provided by
    /// [`SecretProvider`]. This includes signing legacy, segwit and taproot
    /// inputs; including inputs coming from P2PK, P2PKH, P2WPKH,
    /// P2WPKH-in-P2SH, bare scripts, P2SH, P2WSH, P2WSH-in-P2SH and P2TR
    /// outputs with both key- and script- spending paths. Supports all
    /// consensus sighash types.
    ///
    /// # Returns
    ///
    /// Number of created signatures or error. The number of signatures includes
    /// individual signatures created for different P2TR script spending paths,
    /// i.e. a transaction with one P2TR input having a single key may result
    /// in multiple signatures, one per each listed spending P2TR leaf.
    fn sign_all<C>(&mut self, provider: &impl SecretProvider<C>) -> Result<usize, SignError>
    where
        C: Signing + Verification;
}

/// Extension trait for PSBT input signing
pub trait SignInput {
    /// Signs a single PSBT input using all known keys provided by
    /// [`SecretProvider`]. This includes signing legacy and segwit inputs
    /// only; including inputs coming from P2PK, P2PKH, P2WPKH,
    /// P2WPKH-in-P2SH, bare scripts, P2SH, P2WSH, P2WSH-in-P2SH.
    ///
    /// For P2TR input signing use [`SignInput::sign_input_tr`] method.
    ///
    /// This method supports all consensus sighash types.
    ///
    /// # Returns
    ///
    /// Number of created signatures or error.
    fn sign_input_pretr<C, R>(
        &mut self,
        txin: &TxIn,
        index: usize,
        provider: &impl SecretProvider<C>,
        sig_hasher: &mut SigHashCache<R>,
    ) -> Result<usize, SignInputError>
    where
        C: Signing,
        R: Deref<Target = Transaction>;
}

impl SignAll for Psbt {
    fn sign_all<C: Signing + Verification>(
        &mut self,
        provider: &impl SecretProvider<C>,
    ) -> Result<usize, SignError> {
        let mut signature_count = 0usize;
        let tx = self.global.unsigned_tx.clone();
        let mut sig_hasher = SigHashCache::new(&tx);

        self.inputs
            .iter()
            .zip(self.global.unsigned_tx.input.iter())
            .enumerate()
            .map(|(index, (inp, txin))| {
                inp.input_prevout(txin)
                    .map(Clone::clone)
                    .map_err(SignInputError::from)
                    .map_err(|err| SignError::with_input_no(err, index))
            })
            .collect::<Result<Vec<_>, _>>()?;

        for (index, (input, txin)) in self
            .inputs
            .iter_mut()
            .zip(self.global.unsigned_tx.input.iter())
            .enumerate()
        {
            let count = input
                .sign_input_pretr(txin, index, provider, &mut sig_hasher)
                .map_err(|err| SignError::with_input_no(err, index))?;
            signature_count += count;
        }

        Ok(signature_count)
    }
}

impl SignInput for Input {
    fn sign_input_pretr<C, R>(
        &mut self,
        txin: &TxIn,
        index: usize,
        provider: &impl SecretProvider<C>,
        sig_hasher: &mut SigHashCache<R>,
    ) -> Result<usize, SignInputError>
    where
        C: Signing,
        R: Deref<Target = Transaction>,
    {
        let mut signature_count = 0usize;
        let bip32_origins = self.bip32_derivation.clone();

        for (pubkey, (fingerprint, derivation)) in bip32_origins {
            let seckey = match provider.secret_key(fingerprint, &derivation, pubkey.key) {
                Ok(priv_key) => priv_key,
                Err(_) => return Ok(0),
            };

            if sign_input_with(self, txin, index, provider, sig_hasher, pubkey, seckey)? {
                signature_count += 1;
            }
        }

        Ok(signature_count)
    }
}

fn sign_input_with<C, R>(
    input: &mut Input,
    txin: &TxIn,
    index: usize,
    provider: &impl SecretProvider<C>,
    sig_hasher: &mut SigHashCache<R>,
    pubkey: bitcoin::PublicKey,
    mut seckey: secp256k1::SecretKey,
) -> Result<bool, SignInputError>
where
    C: Signing,
    R: Deref<Target = Transaction>,
{
    // Extract & check previous output information
    let prevout = input.input_prevout(txin)?;
    let spent_value = prevout.value;

    // Check script_pubkey match and requirements
    let script_pubkey = PubkeyScript::from_inner(prevout.script_pubkey.clone());
    let witness_script = input.witness_script.as_ref();
    let redeem_script = input.redeem_script.as_ref();

    // Compute sighash
    let sighash_type = input.sighash_type.unwrap_or(EcdsaSigHashType::All);
    let sighash = match input.composite_descr_type(txin)? {
        CompositeDescrType::Wsh
            if Some(&prevout.script_pubkey) != witness_script.map(Script::to_v0_p2wsh).as_ref() =>
        {
            return Err(SignInputError::ScriptPubkeyMismatch)
        }
        CompositeDescrType::Sh | CompositeDescrType::ShWpkh | CompositeDescrType::ShWsh
            if Some(&prevout.script_pubkey) != redeem_script.map(Script::to_p2sh).as_ref() =>
        {
            return Err(SignInputError::ScriptPubkeyMismatch)
        }
        CompositeDescrType::Tr => {
            // skipping taproot spendings: they are handled by a separate function
            return Ok(false);
        }
        CompositeDescrType::Wsh
        | CompositeDescrType::Wpkh
        | CompositeDescrType::ShWsh
        | CompositeDescrType::ShWpkh => sig_hasher.signature_hash(
            index,
            &script_pubkey.script_code(),
            spent_value,
            sighash_type,
        ),
        _ => {
            if input.non_witness_utxo.is_none() {
                return Err(SignInputError::LegacySpentTransactionMissed);
            }
            sig_hasher.signature_hash(
                index,
                &script_pubkey.script_code(),
                spent_value,
                sighash_type,
            )
        }
    };

    // Apply past P2C tweaks
    if let Some(tweak) = input.dbc_p2c_tweak(pubkey.to_public_key().key) {
        seckey
            .add_assign(&tweak[..])
            .map_err(|_| SignInputError::P2cTweak)?;
    }

    // Do the signature
    let signature = provider.secp_context().sign(
        &bitcoin::secp256k1::Message::from_slice(&sighash[..])
            .expect("SigHash generation is broken"),
        &seckey,
    );

    let mut partial_sig = signature.serialize_der().to_vec();
    partial_sig.push(sighash_type.as_u32() as u8);
    input.partial_sigs.insert(pubkey, partial_sig);

    Ok(true)
}
