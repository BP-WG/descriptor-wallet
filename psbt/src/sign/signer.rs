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
use bitcoin::schnorr::TapTweak;
use bitcoin::secp256k1::{self, Signing, Verification};
use bitcoin::util::address::WitnessVersion;
use bitcoin::util::sighash::{self, Prevouts, ScriptPath, SigHashCache};
use bitcoin::util::taproot::TapLeafHash;
use bitcoin::{
    schnorr as bip340, EcdsaSigHashType, PublicKey, SchnorrSigHashType, Script, Transaction,
};
use bitcoin_scripts::PubkeyScript;
use descriptors::{self, CompositeDescrType};
use miniscript::{Miniscript, ToPublicKey};

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

    /// taproot, when signing non-`SIGHASH_ANYONECANPAY` inputs requires
    /// presence of the full spent transaction data, while there is no
    /// `non_witness_utxo` PSBT field for input
    TaprootPrevoutsMissed,

    /// taproot sighash computing error
    #[from]
    TaprootSighashError(sighash::Error),

    /// taproot key signature existing hash type `{prev_sighash_type:?}` does
    /// not match current type `{sighash_type:?}` for input
    TaprootKeySigHashTypeMismatch {
        prev_sighash_type: SchnorrSigHashType,
        sighash_type: SchnorrSigHashType,
    },

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
            SignInputError::TaprootPrevoutsMissed => None,
            SignInputError::TaprootSighashError(err) => Some(err),
            SignInputError::SecpPrivkeyDerivation => None,
            SignInputError::ScriptPubkeyMismatch => None,
            SignInputError::P2cTweak => None,
            SignInputError::TweakFailure(_) => None,
            SignInputError::NonTaprootV1 => None,
            SignInputError::TaprootKeySigHashTypeMismatch { .. } => None,
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
        index: usize,
        provider: &impl SecretProvider<C>,
        sig_hasher: &mut SigHashCache<R>,
    ) -> Result<usize, SignInputError>
    where
        C: Signing,
        R: Deref<Target = Transaction>;

    /// Signs a single PSBT input using all known keys provided by
    /// [`SecretProvider`] for P2TR input spending, including both key- and
    /// script-path spendings.
    ///
    /// For signing other input types pls use [`SignInput::sign_input_pretr`]
    /// method.
    ///
    /// This method supports all consensus sighash types.
    ///
    /// # Returns
    ///
    /// Number of created signatures or error. The number of signatures includes
    /// individual signatures created for different P2TR script spending paths,
    /// i.e. an input having a single key may result in multiple signatures, one
    /// per each listed spending P2TR leaf.
    fn sign_input_tr<C, R>(
        &mut self,
        index: usize,
        provider: &impl SecretProvider<C>,
        sig_hasher: &mut SigHashCache<R>,
        prevouts: &Prevouts,
    ) -> Result<usize, SignInputError>
    where
        C: Signing + Verification,
        R: Deref<Target = Transaction>;
}

impl SignAll for Psbt {
    fn sign_all<C: Signing + Verification>(
        &mut self,
        provider: &impl SecretProvider<C>,
    ) -> Result<usize, SignError> {
        let mut signature_count = 0usize;
        let tx = self.unsigned_tx.clone();
        let mut sig_hasher = SigHashCache::new(&tx);

        let txout_list = self
            .inputs
            .iter()
            .enumerate()
            .map(|(index, inp)| {
                inp.input_prevout()
                    .map(Clone::clone)
                    .map_err(SignInputError::from)
                    .map_err(|err| SignError::with_input_no(err, index))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let prevouts = Prevouts::All(txout_list.as_ref());

        for (index, input) in self.inputs.iter_mut().enumerate() {
            let count = input
                .sign_input_pretr(index, provider, &mut sig_hasher)
                .map_err(|err| SignError::with_input_no(err, index))?;
            if count == 0 {
                signature_count += input
                    .sign_input_tr(index, provider, &mut sig_hasher, &prevouts)
                    .map_err(|err| SignError::with_input_no(err, index))?;
            } else {
                signature_count += count;
            }
        }

        Ok(signature_count)
    }
}

impl SignInput for Input {
    fn sign_input_pretr<C, R>(
        &mut self,
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
            let seckey = match provider.secret_key(fingerprint, &derivation, pubkey) {
                Ok(priv_key) => priv_key,
                Err(_) => continue,
            };

            if sign_input_with(self, index, provider, sig_hasher, pubkey, seckey)? {
                signature_count += 1;
            }
        }

        Ok(signature_count)
    }

    fn sign_input_tr<C, R>(
        &mut self,
        index: usize,
        provider: &impl SecretProvider<C>,
        sig_hasher: &mut SigHashCache<R>,
        prevouts: &Prevouts,
    ) -> Result<usize, SignInputError>
    where
        C: Signing + Verification,
        R: Deref<Target = Transaction>,
    {
        let mut signature_count = 0usize;
        let tr_origins = self.tap_key_origins.clone();

        for (pubkey, (leaves, (fingerprint, derivation))) in tr_origins {
            let keypair = match provider.key_pair(fingerprint, &derivation, pubkey) {
                Ok(pair) => pair,
                Err(_) => continue,
            };

            signature_count += sign_taproot_input_with(
                self, index, provider, sig_hasher, pubkey, keypair, &leaves, prevouts,
            )?;
        }

        Ok(signature_count)
    }
}

fn sign_input_with<C, R>(
    input: &mut Input,
    index: usize,
    provider: &impl SecretProvider<C>,
    sig_hasher: &mut SigHashCache<R>,
    pubkey: secp256k1::PublicKey,
    mut seckey: secp256k1::SecretKey,
) -> Result<bool, SignInputError>
where
    C: Signing,
    R: Deref<Target = Transaction>,
{
    // Extract & check previous output information
    let prevout = input.input_prevout()?;
    let spent_value = prevout.value;

    // Check script_pubkey match and requirements
    let script_pubkey = PubkeyScript::from_inner(prevout.script_pubkey.clone());
    let witness_script = input.witness_script.as_ref();
    let redeem_script = input.redeem_script.as_ref();

    // Compute sighash
    let sighash_type = input.sighash_type.unwrap_or(EcdsaSigHashType::All);
    let sighash = match input.composite_descr_type()? {
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
        | CompositeDescrType::ShWpkh => sig_hasher.segwit_signature_hash(
            index,
            &script_pubkey.script_code(),
            spent_value,
            sighash_type,
        )?,
        _ => {
            if input.non_witness_utxo.is_none() {
                return Err(SignInputError::LegacySpentTransactionMissed);
            }
            sig_hasher.legacy_signature_hash(index, &script_pubkey, sighash_type.as_u32())?
        }
    };

    // Apply past P2C tweaks
    if let Some(tweak) = input.p2c_tweak(pubkey.to_public_key().key) {
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
    input
        .partial_sigs
        .insert(PublicKey::new(pubkey), partial_sig);

    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn sign_taproot_input_with<C, R>(
    input: &mut Input,
    index: usize,
    provider: &impl SecretProvider<C>,
    sig_hasher: &mut SigHashCache<R>,
    pubkey: bip340::PublicKey,
    mut keypair: bip340::KeyPair,
    leaves: &[TapLeafHash],
    prevouts: &Prevouts,
) -> Result<usize, SignInputError>
where
    C: Signing + Verification,
    R: Deref<Target = Transaction>,
{
    let mut signature_count = 0usize;

    // Check script_pubkey match
    let script_pubkey = PubkeyScript::from_inner(input.input_prevout()?.script_pubkey.clone());
    if let Some(internal_key) = input.tap_internal_key {
        if script_pubkey
            != Script::new_v1_p2tr(provider.secp_context(), internal_key, input.tap_merkle_root)
                .into()
        {
            return Err(SignInputError::ScriptPubkeyMismatch);
        }
    }

    // Check that prevouts meets sighash type requirements
    let sighash_type = input.sighash_type.unwrap_or(EcdsaSigHashType::All);
    if matches!(
        (sighash_type, prevouts),
        (
            EcdsaSigHashType::All | EcdsaSigHashType::None | EcdsaSigHashType::Single,
            Prevouts::One(..),
        )
    ) {
        return Err(SignInputError::TaprootPrevoutsMissed);
    }
    let sighash_type = match SchnorrSigHashType::from(sighash_type) {
        SchnorrSigHashType::All => SchnorrSigHashType::Default,
        other => other,
    };

    // Apply past P2C tweaks
    if let Some(tweak) = input.p2c_tweak(pubkey.to_public_key().key) {
        keypair
            .tweak_add_assign(provider.secp_context(), &tweak[..])
            .map_err(|_| SignInputError::P2cTweak)?;
    }

    // Sign taproot script spendings
    for (script, leaf_ver) in input.tap_scripts.values() {
        let tapleaf_hash = TapLeafHash::from_script(script, *leaf_ver);
        if !leaves.contains(&tapleaf_hash) {
            continue;
        }
        let ms: Miniscript<bip340::PublicKey, miniscript::Tap> = Miniscript::parse(script)?;
        for pk in ms.iter_pk() {
            if pk != pubkey {
                continue;
            }
            let sighash = sig_hasher.taproot_signature_hash(
                index,
                prevouts,
                None,
                Some(ScriptPath::with_defaults(script)),
                sighash_type,
            )?;
            let signature = provider.secp_context().schnorrsig_sign(
                &bitcoin::secp256k1::Message::from_slice(&sighash[..])
                    .expect("taproot SigHash generation is broken"),
                &keypair,
            );
            input
                .tap_script_sigs
                .insert((pk, tapleaf_hash), (signature, sighash_type));
            signature_count += 1;
        }
    }

    // Sign taproot key spendings
    let sighash = sig_hasher.taproot_signature_hash(index, prevouts, None, None, sighash_type)?;
    let tweaked_keypair = provider.secp_context().tap_tweak(keypair, None);
    let signature = provider.secp_context().schnorrsig_sign(
        &bitcoin::secp256k1::Message::from_slice(&sighash[..])
            .expect("taproot SigHash generation is broken"),
        &tweaked_keypair.into_inner(),
    );
    signature_count += 1;

    match input.tap_key_sig {
        Some((ref mut prev_signature, prev_sighash_type)) if prev_sighash_type == sighash_type => {
            // TODO: Do non-custom signature aggregation once it will be supported by secp
            let (xr1, s1) = (&signature[..32], &signature[32..]);
            let (xr2, s2) = (&prev_signature[..32], &prev_signature[32..]);
            let (mut r1, mut r2) = ([2u8; 33], [2u8; 33]);
            r1[1..].copy_from_slice(xr1);
            r2[1..].copy_from_slice(xr2);
            let mut r = secp256k1::PublicKey::from_slice(&r1).expect("schnorr sigs are broken");
            let mut s = secp256k1::SecretKey::from_slice(s1).expect("schnorr sigs are broken");
            r.add_exp_assign(provider.secp_context(), &r2)
                .expect("zero negligibility");
            s.add_assign(s2).expect("zero negligibility");
            let mut signature = [0u8; 64];
            signature[..32].copy_from_slice(&r.serialize()[1..]);
            signature[32..].copy_from_slice(&s[..]);
            *prev_signature = secp256k1::schnorrsig::Signature::from_slice(&signature)
                .expect("zero negligibility");
        }
        None => input.tap_key_sig = Some((signature, sighash_type)),
        Some((_, prev_sighash_type)) => {
            return Err(SignInputError::TaprootKeySigHashTypeMismatch {
                prev_sighash_type,
                sighash_type,
            })
        }
    }

    Ok(signature_count)
}
