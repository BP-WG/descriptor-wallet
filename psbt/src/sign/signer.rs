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
use bitcoin::secp256k1::constants::SECRET_KEY_SIZE;
use bitcoin::secp256k1::{self, Signing, Verification};
use bitcoin::util::address::WitnessVersion;
use bitcoin::util::sighash::{self, Prevouts, ScriptPath, SigHashCache};
use bitcoin::util::taproot::TapLeafHash;
use bitcoin::{
    schnorr as bip340, EcdsaSigHashType, PublicKey, SchnorrSigHashType, Script, Transaction, Txid,
};
use bitcoin_scripts::convert::ToP2pkh;
use bitcoin_scripts::{ConvertInfo, PubkeyScript, RedeemScript, WitnessScript};
use descriptors::{self, Deduce, DeductionError};
use miniscript::Miniscript;

use super::KeyProvider;
use crate::{ProprietaryKey, Psbt};

#[derive(Debug, Display, From)]
#[display(doc_comments)]
pub enum SigningError {
    /// provided `non_witness_utxo` TXID {non_witness_utxo_txid} does not match
    /// `prev_out` {txid} from the transaction input #{index}
    WrongInputTxid {
        index: usize,
        non_witness_utxo_txid: Txid,
        txid: Txid,
    },

    /// public key {provided} provided with PSBT input does not match public
    /// key {derived} derived from the supplied private key using
    /// derivation path from that input
    PubkeyMismatch {
        provided: PublicKey,
        derived: PublicKey,
    },

    /// unable to sign future witness version {1} in output #{0}
    FutureWitness(usize, WitnessVersion),

    /// unable to sign non-taproot witness version output #{0}
    NonTaprootV1(usize),

    /// no redeem or witness script specified for input #{0}
    NoPrevoutScript(usize),

    /// input #{0} spending witness output does not contain witness script
    /// source
    NoWitnessScript(usize),

    /// input #{0} must be a witness input since it is supplied with
    /// `witness_utxo` data and does not have `non_witness_utxo`
    NonWitnessInput(usize),

    /// transaction input #{0} is a non-witness input, but full spent
    /// transaction is not provided in the `non_witness_utxo` PSBT field.
    LegacySpentTransactionMissed(usize),

    /// taproot, when signing non-`SIGHASH_ANYONECANPAY` inputs requires
    /// presence of the full spent transaction data, while there is no
    /// `non_witness_utxo` PSBT field for input #{0}
    TaprootPrevoutsMissed(usize),

    /// taproot sighash computing error
    #[from]
    TaprootSighashError(sighash::Error),

    /// taproot key signature existing hash type `{prev_sighash_type:?}` does
    /// not match current type `{sighash_type:?}` for input #{input_index}
    TaprootKeySigHashTypeMismatch {
        input_index: usize,
        prev_sighash_type: SchnorrSigHashType,
        sighash_type: SchnorrSigHashType,
    },

    /// unable to derive private key with a given derivation path: elliptic
    /// curve prime field order (`p`) overflow or derivation resulting at the
    /// point-at-infinity.
    SecpPrivkeyDerivation(usize),

    /// `scriptPubkey` from previous output does not match witness or redeem
    /// script from the same input #{0} supplied in PSBT
    ScriptPubkeyMismatch(usize),

    /// wrong pay-to-contract public key tweak data length in input #{input}:
    /// {len} bytes instead of 32
    WrongTweakLength { input: usize, len: usize },

    /// rrror applying tweak matching public key {1} from input #{0}: the tweak
    /// value is either a modulo-negation of the original private key, or
    /// it leads to elliptic curve prime field order (`p`) overflow
    TweakFailure(usize, secp256k1::PublicKey),

    /// miniscript parse error
    #[from]
    Miniscript(miniscript::Error),
}

impl std::error::Error for SigningError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SigningError::WrongInputTxid { .. } => None,
            SigningError::PubkeyMismatch { .. } => None,
            SigningError::FutureWitness(_, _) => None,
            SigningError::NoPrevoutScript(_) => None,
            SigningError::NoWitnessScript(_) => None,
            SigningError::NonWitnessInput(_) => None,
            SigningError::LegacySpentTransactionMissed(_) => None,
            SigningError::TaprootPrevoutsMissed(_) => None,
            SigningError::TaprootSighashError(err) => Some(err),
            SigningError::SecpPrivkeyDerivation(_) => None,
            SigningError::ScriptPubkeyMismatch(_) => None,
            SigningError::WrongTweakLength { .. } => None,
            SigningError::TweakFailure(_, _) => None,
            SigningError::NonTaprootV1(_) => None,
            SigningError::TaprootKeySigHashTypeMismatch { .. } => None,
            SigningError::Miniscript(err) => Some(err),
        }
    }
}

pub trait Signer {
    fn sign<C: Signing + Verification>(
        &mut self,
        provider: &impl KeyProvider<C>,
    ) -> Result<usize, SigningError>;
    fn sign_input<C: Signing + Verification>(
        &mut self,
        index: usize,
        provider: &impl KeyProvider<C>,
        cache: &mut SigHashCache<&Transaction>,
    ) -> Result<usize, SigningError>;
}

impl Signer for Psbt {
    fn sign<C: Signing + Verification>(
        &mut self,
        provider: &impl KeyProvider<C>,
    ) -> Result<usize, SigningError> {
        let mut signature_count = 0usize;
        let tx = self.unsigned_tx.clone();
        let mut sig_hasher = SigHashCache::new(&tx);

        for index in 0..self.inputs.len() {
            signature_count += self.sign_input(index, provider, &mut sig_hasher)?;
        }

        Ok(signature_count)
    }

    fn sign_input<C: Signing + Verification>(
        &mut self,
        index: usize,
        provider: &impl KeyProvider<C>,
        sig_hasher: &mut SigHashCache<&Transaction>,
    ) -> Result<usize, SigningError> {
        let mut signature_count = 0usize;
        let bip32_origins = self.inputs[index].bip32_derivation.clone();
        let tr_origins = self.inputs[index].tap_key_origins.clone();

        for (pubkey, (fingerprint, derivation)) in bip32_origins {
            let seckey = match provider.secret_key(fingerprint, &derivation, pubkey) {
                Ok(priv_key) => priv_key,
                Err(_) => return Ok(0),
            };

            if sign_input_with(self, index, provider, sig_hasher, pubkey, seckey)? {
                signature_count += 1;
            }
        }

        for (pubkey, (leaves, (fingerprint, derivation))) in tr_origins {
            let keypair = match provider.key_pair(fingerprint, &derivation, pubkey) {
                Ok(pair) => pair,
                Err(_) => return Ok(0),
            };

            signature_count += sign_taproot_input_with(
                self, index, provider, sig_hasher, pubkey, keypair, &leaves,
            )?;
        }

        Ok(signature_count)
    }
}

fn sign_input_with<C: Signing>(
    psbt: &mut Psbt,
    index: usize,
    provider: &impl KeyProvider<C>,
    sig_hasher: &mut SigHashCache<&Transaction>,
    pubkey: secp256k1::PublicKey,
    mut seckey: secp256k1::SecretKey,
) -> Result<bool, SigningError> {
    let txin = &psbt.unsigned_tx.input[index];
    let inp = &mut psbt.inputs[index];

    // Extract & check previous output information
    let (prevouts, script_pubkey, require_witness, spent_value) =
        match (&inp.non_witness_utxo, &inp.witness_utxo) {
            (Some(prev_tx), _) => {
                let prev_txid = prev_tx.txid();
                if prev_txid != txin.previous_output.txid {
                    return Err(SigningError::WrongInputTxid {
                        index,
                        txid: txin.previous_output.txid,
                        non_witness_utxo_txid: prev_txid,
                    });
                }
                let prevout = prev_tx.output[txin.previous_output.vout as usize].clone();
                (
                    Prevouts::All(&prev_tx.output),
                    prevout.script_pubkey,
                    false,
                    prevout.value,
                )
            }
            (None, Some(txout)) => (
                Prevouts::One(index, &txout),
                txout.script_pubkey.clone(),
                true,
                txout.value,
            ),
            _ => return Ok(false),
        };
    let script_pubkey = PubkeyScript::from_inner(script_pubkey);

    // Check script_pubkey match
    if let Some(ref witness_script) = inp.witness_script {
        let witness_script: WitnessScript = WitnessScript::from_inner(witness_script.clone());
        if script_pubkey != witness_script.to_p2wsh()
            && script_pubkey != witness_script.to_p2sh_wsh()
        {
            return Err(SigningError::ScriptPubkeyMismatch(index));
        }
    } else if let Some(ref redeem_script) = inp.redeem_script {
        if require_witness {
            return Err(SigningError::NoWitnessScript(index));
        }
        let redeem_script: RedeemScript = RedeemScript::from_inner(redeem_script.clone());
        if script_pubkey != redeem_script.to_p2sh() {
            return Err(SigningError::ScriptPubkeyMismatch(index));
        }
    } else if Some(&script_pubkey) == pubkey.to_p2pkh().as_ref() {
        if require_witness {
            return Err(SigningError::NonWitnessInput(index));
        }
    } else if Some(&script_pubkey) != pubkey.to_p2wpkh().as_ref()
        && Some(&script_pubkey) != pubkey.to_p2sh_wpkh().as_ref()
    {
        return Err(SigningError::NoPrevoutScript(index));
    }

    let convert_info = ConvertInfo::deduce(
        &script_pubkey,
        inp.witness_script.as_ref().map(|_| true).or(Some(false)),
    )
    .map_err(|err| match err {
        DeductionError::IncompleteInformation => unreachable!(),
        DeductionError::NonTaprootV1 => SigningError::NonTaprootV1(index),
        DeductionError::UnsupportedWitnessVersion(version) => {
            SigningError::FutureWitness(index, version)
        }
    })?;

    let sighash_type = inp.sighash_type.unwrap_or(EcdsaSigHashType::All);
    let sighash = match convert_info {
        // Taproot reqiired dedicated script procedure
        ConvertInfo::Taproot => return Ok(false),
        ConvertInfo::NestedV0 | ConvertInfo::SegWitV0 => sig_hasher.segwit_signature_hash(
            index,
            &script_pubkey.script_code(),
            spent_value,
            sighash_type,
        )?,
        _ => {
            if !matches!(prevouts, Prevouts::All(_)) {
                return Err(SigningError::LegacySpentTransactionMissed(index));
            }
            psbt.unsigned_tx
                .signature_hash(index, &script_pubkey, sighash_type.as_u32())
        }
    };

    // TODO: Properly handle P2SH

    // Apply tweak, if any
    if let Some(tweak) = inp.proprietary.get(&ProprietaryKey {
        prefix: b"P2C".to_vec(),
        subtype: 0,
        key: pubkey.serialize().to_vec(),
    }) {
        if tweak.len() != SECRET_KEY_SIZE {
            return Err(SigningError::WrongTweakLength {
                input: index,
                len: tweak.len(),
            });
        }
        seckey
            .add_assign(tweak)
            .map_err(|_| SigningError::TweakFailure(index, pubkey))?;
    }

    let signature = provider.secp_context().sign(
        &bitcoin::secp256k1::Message::from_slice(&sighash[..])
            .expect("SigHash generation is broken"),
        &seckey,
    );

    let mut partial_sig = signature.serialize_der().to_vec();
    partial_sig.push(sighash_type.as_u32() as u8);
    inp.partial_sigs.insert(PublicKey::new(pubkey), partial_sig);

    Ok(true)
}

fn sign_taproot_input_with<C: Signing + Verification>(
    psbt: &mut Psbt,
    index: usize,
    provider: &impl KeyProvider<C>,
    sig_hasher: &mut SigHashCache<&Transaction>,
    pubkey: bip340::PublicKey,
    keypair: bip340::KeyPair,
    leaves: &[TapLeafHash],
) -> Result<usize, SigningError> {
    let mut signature_count = 0usize;

    let txin = &psbt.unsigned_tx.input[index];
    let inp = &mut psbt.inputs[index];

    let (prevouts, script_pubkey) = match (&inp.non_witness_utxo, &inp.witness_utxo) {
        (Some(prev_tx), _) => {
            let prev_txid = prev_tx.txid();
            if prev_txid != txin.previous_output.txid {
                return Err(SigningError::WrongInputTxid {
                    index,
                    txid: txin.previous_output.txid,
                    non_witness_utxo_txid: prev_txid,
                });
            }
            let prevout = prev_tx.output[txin.previous_output.vout as usize].clone();
            (Prevouts::All(&prev_tx.output), prevout.script_pubkey)
        }
        (None, Some(txout)) => (Prevouts::One(index, &txout), txout.script_pubkey.clone()),
        _ => return Ok(0),
    };

    let script_pubkey = PubkeyScript::from_inner(script_pubkey);
    if let Some(internal_key) = inp.tap_internal_key {
        if script_pubkey
            != Script::new_v1_p2tr(&provider.secp_context(), internal_key, inp.tap_merkle_root)
                .into()
        {
            return Err(SigningError::ScriptPubkeyMismatch(index));
        }
    }

    let sighash_type = inp.sighash_type.unwrap_or(EcdsaSigHashType::All);
    if matches!(
        (sighash_type, &prevouts),
        (
            EcdsaSigHashType::All | EcdsaSigHashType::None | EcdsaSigHashType::Single,
            Prevouts::One(..),
        )
    ) {
        return Err(SigningError::TaprootPrevoutsMissed(index));
    }
    let sighash_type = SchnorrSigHashType::from(sighash_type);

    // Sign taproot script spendings
    for (_, (script, leaf_ver)) in &inp.tap_scripts {
        let tapleaf_hash = TapLeafHash::from_script(script, *leaf_ver);
        if !leaves.contains(&tapleaf_hash) {
            continue;
        }
        let ms: Miniscript<bip340::PublicKey, miniscript::Tap> = Miniscript::parse(&script)?;
        for pk in ms.iter_pk() {
            if pk != pubkey {
                continue;
            }
            let sighash = sig_hasher.taproot_signature_hash(
                index,
                &prevouts,
                None,
                Some(ScriptPath::with_defaults(&script)),
                sighash_type,
            )?;
            let signature = provider.secp_context().schnorrsig_sign(
                &bitcoin::secp256k1::Message::from_slice(&sighash[..])
                    .expect("taproot SigHash generation is broken"),
                &keypair,
            );
            inp.tap_script_sigs
                .insert((pk, tapleaf_hash), (signature, sighash_type));
            signature_count += 1;
        }
    }

    // TODO: Apply P2C tweaks

    // Sign taproot key spendings
    let sighash = sig_hasher.taproot_signature_hash(index, &prevouts, None, None, sighash_type)?;
    let signature = provider.secp_context().schnorrsig_sign(
        &bitcoin::secp256k1::Message::from_slice(&sighash[..])
            .expect("taproot SigHash generation is broken"),
        &keypair,
    );
    signature_count += 1;

    match inp.tap_key_sig {
        Some((_key_sign, prev_sighash_type)) if prev_sighash_type == sighash_type => {
            // TODO: Do signature aggregation once it will be supported by secp
        }
        None => inp.tap_key_sig = Some((signature, sighash_type)),
        Some((_, prev_sighash_type)) => {
            return Err(SigningError::TaprootKeySigHashTypeMismatch {
                input_index: index,
                prev_sighash_type,
                sighash_type,
            })
        }
    }

    Ok(signature_count)
}
