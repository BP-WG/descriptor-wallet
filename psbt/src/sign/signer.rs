// Descriptor wallet library extending bitcoin & miniscript functionality
// by LNP/BP Association (https://lnp-bp.org)
// Written in 2020-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
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

#![allow(clippy::result_large_err)]

use core::ops::Deref;

use amplify::Wrapper;
use bitcoin::hashes::Hash;
use bitcoin::schnorr::TapTweak;
use bitcoin::secp256k1::{self, KeyPair, Signing, Verification, XOnlyPublicKey};
use bitcoin::util::address::WitnessVersion;
use bitcoin::util::sighash::{self, Prevouts, ScriptPath, SighashCache};
use bitcoin::util::taproot::TapLeafHash;
use bitcoin::{
    EcdsaSig, EcdsaSighashType, PubkeyHash, PublicKey, SchnorrSig, SchnorrSighashType, Script,
    Transaction, TxOut,
};
use bitcoin_scripts::{PubkeyScript, RedeemScript};
use descriptors::{CompositeDescrType, DeductionError};
use miniscript::{Miniscript, ToPublicKey};

use super::SecretProvider;
use crate::{Input, InputMatchError, Psbt};

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

    /// input spending P2WSH or P2WSH-in-P2SH must contain witness script
    NoWitnessScript,

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
    TaprootKeySighashTypeMismatch {
        prev_sighash_type: SchnorrSighashType,
        sighash_type: SchnorrSighashType,
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

    /// error applying tweak matching public key {0}: the tweak
    /// value is either a modulo-negation of the original private key, or
    /// it leads to elliptic curve prime field order (`p`) overflow
    TweakFailure(secp256k1::PublicKey),

    /// miniscript parse error
    #[from]
    Miniscript(miniscript::Error),

    /// non-standard sig hash type {sighash_type} used in PSBT for input {index}
    NonStandardSighashType { sighash_type: u32, index: usize },

    /// trying to add to aggregated signature second copy of the signature made
    /// made with the negation of the key (previous sig `R` value is {0}, added
    /// sig `R` value is {1}).
    RepeatedSig(secp256k1::PublicKey, secp256k1::PublicKey),

    /// trying to add to aggregated signature another signature with non-unique
    /// nonce value (previous `s` value is {0}, added nonce value is {1:02x?}).
    RepeatedSigNonce(String, Box<[u8]>),
}

impl std::error::Error for SignInputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SignInputError::FutureWitness(_) => None,
            SignInputError::NoPrevoutScript => None,
            SignInputError::NoRedeemScript => None,
            SignInputError::NoWitnessScript => None,
            SignInputError::LegacySpentTransactionMissed => None,
            SignInputError::TaprootPrevoutsMissed => None,
            SignInputError::TaprootSighashError(err) => Some(err),
            SignInputError::SecpPrivkeyDerivation => None,
            SignInputError::ScriptPubkeyMismatch => None,
            SignInputError::P2cTweak => None,
            SignInputError::TweakFailure(_) => None,
            SignInputError::NonTaprootV1 => None,
            SignInputError::TaprootKeySighashTypeMismatch { .. } => None,
            SignInputError::Miniscript(err) => Some(err),
            SignInputError::PubkeyMismatch { .. } => None,
            SignInputError::Match(err) => Some(err),
            SignInputError::InvalidRedeemScript => None,
            SignInputError::NonStandardSighashType { .. } => None,
            SignInputError::RepeatedSig(..) => None,
            SignInputError::RepeatedSigNonce(..) => None,
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

impl SignAll for Psbt {
    fn sign_all<C: Signing + Verification>(
        &mut self,
        provider: &impl SecretProvider<C>,
    ) -> Result<usize, SignError> {
        let tx = self.clone().into_unsigned_tx();
        let mut signature_count = 0usize;
        let mut sig_hasher = SighashCache::new(&tx);

        let txout_list = self
            .inputs
            .iter()
            .map(|input| {
                input
                    .input_prevout()
                    .cloned()
                    .map_err(SignInputError::from)
                    .map_err(|err| SignError::with_input_no(err, input.index()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let prevouts = Prevouts::All(txout_list.as_ref());

        for input in &mut self.inputs {
            let count = input
                .sign_input_pretr(provider, &mut sig_hasher)
                .map_err(|err| SignError::with_input_no(err, input.index()))?;
            if count == 0 {
                signature_count += input
                    .sign_input_tr(provider, &mut sig_hasher, &prevouts)
                    .map_err(|err| SignError::with_input_no(err, input.index()))?;
            } else {
                signature_count += count;
            }
        }

        Ok(signature_count)
    }
}

impl Input {
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
        provider: &impl SecretProvider<C>,
        sig_hasher: &mut SighashCache<R>,
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

            if self.sign_input_with(provider, sig_hasher, pubkey, seckey)? {
                signature_count += 1;
            }
        }

        Ok(signature_count)
    }

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
        provider: &impl SecretProvider<C>,
        sig_hasher: &mut SighashCache<R>,
        prevouts: &Prevouts<TxOut>,
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

            signature_count += self.sign_taproot_input_with(
                provider, sig_hasher, pubkey, keypair, &leaves, prevouts,
            )?;
        }

        Ok(signature_count)
    }

    fn sign_input_with<C, R>(
        &mut self,
        provider: &impl SecretProvider<C>,
        sig_hasher: &mut SighashCache<R>,
        pubkey: secp256k1::PublicKey,
        mut seckey: secp256k1::SecretKey,
    ) -> Result<bool, SignInputError>
    where
        C: Signing,
        R: Deref<Target = Transaction>,
    {
        // Extract & check previous output information
        let index = self.index();
        let prevout = self.input_prevout()?;
        let spent_value = prevout.value;

        // Check script_pubkey match and requirements
        let script_pubkey = PubkeyScript::from_inner(prevout.script_pubkey.clone());
        let witness_script = self.witness_script.as_ref();
        let redeem_script = self.redeem_script.as_ref();

        // Compute sighash
        let sighash_type = self
            .sighash_type
            .map(|sht| sht.ecdsa_hash_ty())
            .transpose()
            .map_err(|err| SignInputError::NonStandardSighashType {
                sighash_type: err.0,
                index,
            })?
            .unwrap_or(EcdsaSighashType::All);

        let descr_type =
            CompositeDescrType::deduce(&script_pubkey, redeem_script, witness_script.is_some())?;
        let sighash = match (descr_type, witness_script) {
            (CompositeDescrType::Wsh, Some(witness_script))
                if prevout.script_pubkey != witness_script.to_v0_p2wsh() =>
            {
                return Err(SignInputError::ScriptPubkeyMismatch)
            }
            (CompositeDescrType::Sh, _)
            | (CompositeDescrType::ShWpkh, _)
            | (CompositeDescrType::ShWsh, _)
                if Some(&prevout.script_pubkey)
                    != redeem_script
                        .map(RedeemScript::to_p2sh)
                        .map(Into::into)
                        .as_ref() =>
            {
                return Err(SignInputError::ScriptPubkeyMismatch)
            }
            (CompositeDescrType::Tr, _) => {
                // skipping taproot spendings: they are handled by a separate function
                return Ok(false);
            }
            (CompositeDescrType::Wpkh, _) | (CompositeDescrType::ShWpkh, _) => {
                let pubkey_hash = PubkeyHash::from_slice(&script_pubkey[2..22])
                    .expect("PubkeyHash hash length failure");
                let script_code = Script::new_p2pkh(&pubkey_hash);
                sig_hasher.segwit_signature_hash(index, &script_code, spent_value, sighash_type)?
            }
            (CompositeDescrType::Wsh, Some(witness_script))
            | (CompositeDescrType::ShWsh, Some(witness_script)) => sig_hasher
                .segwit_signature_hash(index, witness_script, spent_value, sighash_type)?,
            (CompositeDescrType::Wsh, None) | (CompositeDescrType::ShWsh, None) => {
                return Err(SignInputError::NoWitnessScript)
            }
            _ => {
                if self.non_witness_utxo.is_none() {
                    return Err(SignInputError::LegacySpentTransactionMissed);
                }
                sig_hasher.legacy_signature_hash(index, &script_pubkey, sighash_type.to_u32())?
            }
        };

        // Apply past P2C tweaks
        if let Some(tweak) = self.p2c_tweak(pubkey) {
            let tweak = secp256k1::Scalar::from_be_bytes(tweak.into_inner())
                .expect("negligible probability");
            seckey = seckey
                .add_tweak(&tweak)
                .map_err(|_| SignInputError::P2cTweak)?;
        }

        // Do the signature
        let signature = provider.secp_context().sign_ecdsa(
            &bitcoin::secp256k1::Message::from_slice(&sighash[..])
                .expect("Sighash generation is broken"),
            &seckey,
        );

        let mut partial_sig = signature.serialize_der().to_vec();
        partial_sig.push(sighash_type as u8);
        self.partial_sigs.insert(
            bitcoin::PublicKey::new(pubkey),
            EcdsaSig::from_slice(&partial_sig).expect("serialize_der failure"),
        );

        Ok(true)
    }

    fn sign_taproot_input_with<C, R>(
        &mut self,
        provider: &impl SecretProvider<C>,
        sig_hasher: &mut SighashCache<R>,
        pubkey: XOnlyPublicKey,
        mut keypair: KeyPair,
        leaves: &[TapLeafHash],
        prevouts: &Prevouts<TxOut>,
    ) -> Result<usize, SignInputError>
    where
        C: Signing + Verification,
        R: Deref<Target = Transaction>,
    {
        let mut signature_count = 0usize;
        let index = self.index();

        // Check script_pubkey match
        let script_pubkey = PubkeyScript::from_inner(self.input_prevout()?.script_pubkey.clone());
        if let Some(internal_key) = self.tap_internal_key {
            if script_pubkey
                != Script::new_v1_p2tr(provider.secp_context(), internal_key, self.tap_merkle_root)
                    .into()
            {
                return Err(SignInputError::ScriptPubkeyMismatch);
            }
        }

        // Check that prevouts meets sighash type requirements
        let sighash_type = self
            .sighash_type
            .map(|sht| sht.schnorr_hash_ty())
            .transpose()
            .map_err(|_| SignInputError::NonStandardSighashType {
                sighash_type: self.sighash_type.expect("option unwrapped above").to_u32(),
                index,
            })?
            .unwrap_or(SchnorrSighashType::Default);
        if matches!(
            (sighash_type, prevouts),
            (
                SchnorrSighashType::All
                    | SchnorrSighashType::None
                    | SchnorrSighashType::Single
                    | SchnorrSighashType::Default,
                Prevouts::One(..),
            )
        ) {
            return Err(SignInputError::TaprootPrevoutsMissed);
        }

        // Apply past P2C tweaks
        if let Some(tweak) = self.p2c_tweak(pubkey.to_public_key().inner) {
            let tweak = secp256k1::Scalar::from_be_bytes(tweak.into_inner())
                .expect("negligible probability");
            keypair = keypair
                .add_xonly_tweak(provider.secp_context(), &tweak)
                .map_err(|_| SignInputError::P2cTweak)?;
        }

        // Sign taproot script spendings
        for (script, leaf_ver) in self.tap_scripts.values() {
            let tapleaf_hash = TapLeafHash::from_script(script, *leaf_ver);
            if !leaves.contains(&tapleaf_hash) {
                continue;
            }
            let ms: Miniscript<XOnlyPublicKey, miniscript::Tap> = Miniscript::parse(script)?;
            for pk in ms.iter_pk() {
                if pk != pubkey {
                    continue;
                }
                let sighash = sig_hasher.taproot_script_spend_signature_hash(
                    index,
                    prevouts,
                    ScriptPath::with_defaults(script),
                    sighash_type,
                )?;
                let signature = provider.secp_context().sign_schnorr(
                    &bitcoin::secp256k1::Message::from_slice(&sighash[..])
                        .expect("taproot Sighash generation is broken"),
                    &keypair,
                );
                let sig = SchnorrSig {
                    sig: signature,
                    hash_ty: sighash_type,
                };
                self.tap_script_sigs.insert((pk, tapleaf_hash), sig);
                signature_count += 1;
            }
        }

        // Sign taproot key spendings
        let sighash =
            sig_hasher.taproot_signature_hash(index, prevouts, None, None, sighash_type)?;
        let tweaked_keypair = keypair.tap_tweak(provider.secp_context(), self.tap_merkle_root);
        let signature = provider.secp_context().sign_schnorr(
            &bitcoin::secp256k1::Message::from_slice(&sighash[..])
                .expect("taproot Sighash generation is broken"),
            &tweaked_keypair.to_inner(),
        );

        match self.tap_key_sig {
            Some(_) if !provider.use_musig() => {
                // Skip signature aggregation
            }
            None if !provider.use_musig()
                && (self.tap_internal_key != Some(keypair.x_only_public_key().0)
                    || self.tap_internal_key.is_none()) =>
            {
                // Skip creating partial sig
            }
            Some(SchnorrSig {
                sig: ref mut prev_signature,
                hash_ty: prev_sighash_type,
            }) if prev_sighash_type == sighash_type => {
                // TODO: Do non-custom signature aggregation once it will be supported by secp
                let (xr1, s1) = (&signature[..32], &signature[32..]);
                let (xr2, s2) = (&prev_signature[..32], &prev_signature[32..]);
                let (mut r1, mut r2) = ([2u8; 33], [2u8; 33]);
                r1[1..].copy_from_slice(xr1);
                r2[1..].copy_from_slice(xr2);
                let mut r = secp256k1::PublicKey::from_slice(&r1).expect("schnorr sigs are broken");
                let r2 = secp256k1::PublicKey::from_slice(&r2).expect("schnorr sigs are broken");
                let mut s = secp256k1::SecretKey::from_slice(s1).expect("schnorr sigs are broken");
                r = r
                    .combine(&r2)
                    .map_err(|_| SignInputError::RepeatedSig(r, r2))?;
                let mut tweak = [0u8; 32];
                tweak.copy_from_slice(s2);
                let tweak =
                    secp256k1::Scalar::from_be_bytes(tweak).expect("negligible probability");
                s = s.add_tweak(&tweak).map_err(|_| {
                    SignInputError::RepeatedSigNonce(s.display_secret().to_string(), Box::from(s2))
                })?;
                let mut signature = [0u8; 64];
                signature[..32].copy_from_slice(&r.serialize()[1..]);
                signature[32..].copy_from_slice(&s[..]);
                *prev_signature = secp256k1::schnorr::Signature::from_slice(&signature)
                    .expect("zero negligibility");
                signature_count += 1;
            }
            None => {
                self.tap_key_sig = Some(SchnorrSig {
                    sig: signature,
                    hash_ty: sighash_type,
                });
                signature_count += 1;
            }
            Some(SchnorrSig {
                hash_ty: prev_sighash_type,
                ..
            }) => {
                return Err(SignInputError::TaprootKeySighashTypeMismatch {
                    prev_sighash_type,
                    sighash_type,
                })
            }
        }

        Ok(signature_count)
    }
}
