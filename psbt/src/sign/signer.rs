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
use bitcoin::secp256k1::Signing;
use bitcoin::util::bip143::SigHashCache;
use bitcoin::{PublicKey, SigHashType, Txid};
use bitcoin_scripts::{
    Category, PubkeyScript, RedeemScript, ToP2pkh, WitnessScript,
};
use descriptors::{self, Deduce};

use super::KeyProvider;
use crate::v0::Psbt;
use crate::ProprietaryKey;

// TODO #17: Derive `Ord`, `Hash` once `SigHashType` will support it
#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum SigningError {
    /// Provided `non_witness_utxo` TXID {non_witness_utxo_txid} does not match
    /// `prev_out` {txid} from the transaction input #{index}
    WrongInputTxid {
        index: usize,
        non_witness_utxo_txid: Txid,
        txid: Txid,
    },

    /// Input #{0} requires custom sighash type `{1}`, while only `SIGHASH_ALL`
    /// is allowed
    SigHashType(usize, SigHashType),

    /// Public key {provided} provided with PSBT input does not match public
    /// key {derived} derived from the supplied private key using
    /// derivation path from that input
    PubkeyMismatch {
        provided: PublicKey,
        derived: PublicKey,
    },

    /// No redeem or witness script specified for input #{0}
    NoPrevoutScript(usize),

    /// Input #{0} spending witness output does not contain witness script
    /// source
    NoWitnessScript(usize),

    /// Input #{0} must be a witness input since it is supplied with
    /// `witness_utxo` data and does not have `non_witness_utxo`
    NonWitnessInput(usize),

    /// Unable to derive private key with a given derivation path: elliptic
    /// curve prime field order (`p`) overflow or derivation resulting at the
    /// point-at-infinity.
    SecpPrivkeyDerivation(usize),

    /// `scriptPubkey` from previous output does not match witness or redeem
    /// script from the same input #{0} supplied in PSBT
    ScriptPubkeyMismatch(usize),

    /// Wrong pay-to-contract public key tweak data length in input #{input}:
    /// {len} bytes instead of 32
    WrongTweakLength { input: usize, len: usize },

    /// Error applying tweak matching public key {1} from input #{0}: the tweak
    /// value is either a modulo-negation of the original private key, or
    /// it leads to elliptic curve prime field order (`p`) overflow
    TweakFailure(usize, PublicKey),
}

pub trait Signer {
    fn sign<C: Signing>(
        &mut self,
        provider: &impl KeyProvider<C>,
    ) -> Result<usize, SigningError>;
}

impl Signer for Psbt {
    fn sign<C: Signing>(
        &mut self,
        provider: &impl KeyProvider<C>,
    ) -> Result<usize, SigningError> {
        let mut signature_count = 0usize;
        let tx = self.global.unsigned_tx.clone();
        let mut sig_hasher = SigHashCache::new(&mut self.global.unsigned_tx);
        for (index, inp) in self.inputs.iter_mut().enumerate() {
            let txin = tx.input[index].clone();
            for (pubkey, (fingerprint, derivation)) in &inp.bip32_derivation {
                let mut priv_key = match provider.secret_key(
                    *fingerprint,
                    derivation,
                    pubkey.key,
                ) {
                    Ok(priv_key) => priv_key,
                    Err(_) => continue,
                };

                // Extract & check previous output information
                let (script_pubkey, require_witness, spent_value) =
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
                            let prevout = prev_tx.output
                                [txin.previous_output.vout as usize]
                                .clone();
                            (prevout.script_pubkey, false, prevout.value)
                        }
                        (None, Some(txout)) => {
                            (txout.script_pubkey.clone(), true, txout.value)
                        }
                        _ => continue,
                    };
                let script_pubkey = PubkeyScript::from_inner(script_pubkey);

                if let Some(sighash_type) = inp.sighash_type {
                    if sighash_type != SigHashType::All {
                        return Err(SigningError::SigHashType(
                            index,
                            sighash_type,
                        ));
                    }
                }

                // Check script_pubkey match
                if let Some(ref witness_script) = inp.witness_script {
                    let witness_script: WitnessScript =
                        WitnessScript::from_inner(witness_script.clone());
                    if script_pubkey != witness_script.to_p2wsh()
                        && script_pubkey != witness_script.to_p2sh_wsh()
                    {
                        return Err(SigningError::ScriptPubkeyMismatch(index));
                    }
                } else if let Some(ref redeem_script) = inp.redeem_script {
                    if require_witness {
                        return Err(SigningError::NoWitnessScript(index));
                    }
                    let redeem_script: RedeemScript =
                        RedeemScript::from_inner(redeem_script.clone());
                    if script_pubkey != redeem_script.to_p2sh() {
                        return Err(SigningError::ScriptPubkeyMismatch(index));
                    }
                } else if script_pubkey == pubkey.to_p2pkh() {
                    if require_witness {
                        return Err(SigningError::NonWitnessInput(index));
                    }
                } else if script_pubkey != pubkey.to_p2wpkh()
                    && script_pubkey != pubkey.to_p2sh_wpkh()
                {
                    return Err(SigningError::NoPrevoutScript(index));
                }

                let is_segwit = Category::deduce(
                    &script_pubkey,
                    inp.witness_script.as_ref().map(|_| true),
                )
                .map(Category::is_witness)
                .unwrap_or(true);

                let sighash_type = SigHashType::All;
                let sighash = if is_segwit {
                    sig_hasher.signature_hash(
                        index,
                        &script_pubkey.script_code(),
                        spent_value,
                        sighash_type,
                    )
                } else {
                    tx.signature_hash(
                        index,
                        &script_pubkey,
                        sighash_type.as_u32(),
                    )
                };

                // Apply tweak, if any
                if let Some(tweak) = inp.proprietary.get(&ProprietaryKey {
                    prefix: b"P2C".to_vec(),
                    subtype: 0,
                    key: pubkey.to_bytes(),
                }) {
                    if tweak.len() != SECRET_KEY_SIZE {
                        return Err(SigningError::WrongTweakLength {
                            input: index,
                            len: tweak.len(),
                        });
                    }
                    priv_key.add_assign(tweak).map_err(|_| {
                        SigningError::TweakFailure(index, *pubkey)
                    })?;
                }

                let signature = provider.secp_context().sign(
                    &bitcoin::secp256k1::Message::from_slice(&sighash[..])
                        .expect("SigHash generation is broken"),
                    &priv_key,
                );
                unsafe {
                    priv_key.as_mut_ptr().copy_from(
                        [0u8; SECRET_KEY_SIZE].as_ptr(),
                        SECRET_KEY_SIZE,
                    )
                };

                let mut partial_sig = signature.serialize_der().to_vec();
                partial_sig.push(sighash_type.as_u32() as u8);
                inp.sighash_type = Some(sighash_type);
                inp.partial_sigs.insert(*pubkey, partial_sig);
                signature_count += 1;
            }
        }

        Ok(signature_count)
    }
}
