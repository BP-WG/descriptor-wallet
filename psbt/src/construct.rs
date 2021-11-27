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

//! Functions, errors and traits specific for PSBT constructor role.

use bitcoin::secp256k1::{Secp256k1, Verification};
use bitcoin::util::taproot::{LeafVersion, TapLeafHash};
use bitcoin::{Address, Script, Transaction, TxIn, TxOut, Txid};
use bitcoin_hd::{DeriveError, DescriptorDerive, SegmentIndexes, TrackingAccount, UnhardenedIndex};
use bitcoin_onchain::resolvers::{TxResolver, TxResolverError};
use descriptors::locks::LockTime;
use descriptors::InputDescriptor;
use miniscript::{Descriptor, DescriptorTrait, ForEachKey, ToPublicKey};

use crate::{Input, Output, Psbt};

#[derive(Debug, Display, From)]
#[display(doc_comments)]
pub enum Error {
    /// unable to construct PSBT due to one of transaction inputs is not known
    #[from]
    ResolvingTx(TxResolverError),

    /// unable to construct PSBT due to failing key derivetion derivation
    #[from]
    Derive(DeriveError),

    /// unable to construct PSBT due to spent transaction {0} not having
    /// referenced output #{1}
    OutputUnknown(Txid, u32),

    /// derived scriptPubkey `{3}` does not match transaction scriptPubkey
    /// `{2}` for {0}:{1}
    ScriptPubkeyMismatch(Txid, u32, Script, Script),

    /// one of PSBT outputs has invalid script data
    #[from]
    Miniscript(miniscript::Error),

    /// PSBT can't be constructed according to the consensus rules since
    /// it spends more ({output} sats) than the sum of its input amounts
    /// ({input} sats)
    Inflation {
        /// Amount spent: input amounts
        input: u64,

        /// Amount sent: sum of output value + transaction fee
        output: u64,
    },
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::ResolvingTx(err) => Some(err),
            Error::Derive(err) => Some(err),
            Error::OutputUnknown(_, _) => None,
            Error::ScriptPubkeyMismatch(_, _, _, _) => None,
            Error::Miniscript(err) => Some(err),
            Error::Inflation { .. } => None,
        }
    }
}

pub trait Construct {
    #[allow(clippy::too_many_arguments)]
    fn construct<C: Verification>(
        secp: &Secp256k1<C>,
        descriptor: &Descriptor<TrackingAccount>,
        lock_time: LockTime,
        inputs: &[InputDescriptor],
        outputs: &[(Address, u64)],
        change_index: UnhardenedIndex,
        fee: u64,
        tx_resolver: &impl TxResolver,
    ) -> Result<Psbt, Error>;
}

impl Construct for Psbt {
    fn construct<C: Verification>(
        secp: &Secp256k1<C>,
        descriptor: &Descriptor<TrackingAccount>,
        lock_time: LockTime,
        inputs: &[InputDescriptor],
        outputs: &[(Address, u64)],
        change_index: UnhardenedIndex,
        fee: u64,
        tx_resolver: &impl TxResolver,
    ) -> Result<Psbt, Error> {
        let network = descriptor.network()?;
        let mut outputs = outputs.to_vec();

        let mut xpub = bmap! {};
        descriptor.for_each_key(|key| {
            let account = key.as_key();
            if let Some(key_source) = account.account_key_source() {
                xpub.insert(account.account_xpub, key_source);
            }
            true
        });

        let mut total_spent = 0u64;
        let psbt_inputs = inputs
            .iter()
            .map(|input| {
                let txid = input.outpoint.txid;
                let tx = tx_resolver.resolve(&txid)?;
                let output = tx
                    .output
                    .get(input.outpoint.vout as usize)
                    .ok_or(Error::OutputUnknown(txid, input.outpoint.vout))?;
                let output_descriptor = descriptor.derive_descriptor(secp, &input.terminal)?;
                let script_pubkey = output_descriptor.script_pubkey()?;
                if output.script_pubkey != script_pubkey {
                    return Err(Error::ScriptPubkeyMismatch(
                        txid,
                        input.outpoint.vout,
                        output.script_pubkey.clone(),
                        script_pubkey,
                    ));
                }
                let lock_script = output_descriptor.explicit_script()?;
                let mut bip32_derivation = bmap! {};
                let result = descriptor.for_each_key(|key| {
                    let account = key.as_key();
                    match account.bip32_derivation(secp, &input.terminal) {
                        Ok((pubkey, key_source)) => {
                            bip32_derivation.insert(pubkey, key_source);
                            true
                        }
                        Err(_) => false,
                    }
                });
                if !result {
                    return Err(DeriveError::DerivePatternMismatch.into());
                }

                total_spent += output.value;

                let dtype = descriptors::CompositeDescrType::from(&output_descriptor);
                let mut psbt_input = Input {
                    bip32_derivation,
                    sighash_type: Some(input.sighash_type),
                    ..Default::default()
                };
                if dtype.is_segwit() {
                    psbt_input.witness_utxo = Some(output.clone());
                } else {
                    psbt_input.non_witness_utxo = Some(tx.clone());
                }
                if let Descriptor::Tr(mut tr) = output_descriptor {
                    psbt_input.bip32_derivation.clear();
                    psbt_input.tap_merkle_root = tr.spend_info(secp).merkle_root();
                    psbt_input.tap_internal_key = Some(tr.internal_key().to_x_only_pubkey());
                    if let Some(taptree) = tr.taptree() {
                        descriptor.for_each_key(|key| {
                            let (pubkey, key_source) = key
                                .as_key()
                                .bip32_derivation(secp, &input.terminal)
                                .expect("failing on second pass of the same function");
                            let mut leaves = vec![];
                            for (_, ms) in taptree.iter() {
                                for pk in ms.iter_pk() {
                                    if pk == pubkey {
                                        leaves.push(TapLeafHash::from_script(
                                            &ms.encode(),
                                            LeafVersion::TapScript,
                                        ));
                                    }
                                }
                            }
                            let entry = psbt_input
                                .tap_key_origins
                                .entry(pubkey.to_x_only_pubkey())
                                .or_insert((vec![], key_source));
                            entry.0.extend(leaves);
                            true
                        });
                    }
                    descriptor.for_each_key(|key| {
                        let (pubkey, key_source) = key
                            .as_key()
                            .bip32_derivation(secp, &input.terminal)
                            .expect("failing on second pass of the same function");
                        if pubkey == *tr.internal_key() {
                            psbt_input
                                .tap_key_origins
                                .entry(pubkey.to_x_only_pubkey())
                                .or_insert((vec![], key_source));
                        }
                        true
                    });
                } else {
                    if dtype.has_redeem_script() {
                        psbt_input.redeem_script = Some(lock_script.clone());
                    }
                    if dtype.has_witness_script() {
                        psbt_input.witness_script = Some(lock_script);
                    }
                }
                Ok(psbt_input)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut psbt_outputs: Vec<_> = outputs.iter().map(|_| Output::default()).collect();

        let total_sent: u64 = outputs.iter().map(|(_, amount)| amount).sum();

        let change = match total_spent.checked_sub(total_sent + fee) {
            Some(change) => change,
            None => {
                return Err(Error::Inflation {
                    input: total_spent,
                    output: total_sent + fee,
                })
            }
        };

        if change > 0 {
            let change_derivation = [UnhardenedIndex::one(), change_index];
            let change_descriptor = descriptor.derive_descriptor(secp, &change_derivation)?;
            let change_address = change_descriptor.address(network)?;
            outputs.push((change_address, change));
            let mut bip32_derivation = bmap! {};
            descriptor.for_each_key(|key| {
                let account = key.as_key();
                let (pubkey, key_source) = account
                    .bip32_derivation(secp, &change_derivation)
                    .expect("already tested descriptor derivation mismatch");
                bip32_derivation.insert(pubkey, key_source);
                true
            });

            let lock_script = change_descriptor.explicit_script()?;
            let dtype = descriptors::CompositeDescrType::from(&change_descriptor);
            let mut psbt_change_output = Output {
                bip32_derivation,
                ..Default::default()
            };
            if dtype.has_redeem_script() {
                psbt_change_output.redeem_script = Some(lock_script.clone());
            }
            if dtype.has_witness_script() {
                psbt_change_output.witness_script = Some(lock_script);
            }
            psbt_outputs.push(psbt_change_output);
        }

        let spending_tx = Transaction {
            version: 2,
            lock_time: lock_time.as_u32(),
            input: inputs
                .iter()
                .map(|input| TxIn {
                    previous_output: input.outpoint,
                    sequence: input.seq_no.as_u32(),
                    ..Default::default()
                })
                .collect(),
            output: outputs
                .into_iter()
                .map(|output| TxOut {
                    value: output.1,
                    script_pubkey: output.0.script_pubkey(),
                })
                .collect(),
        };

        Ok(Psbt {
            unsigned_tx: spending_tx,
            version: 0,
            xpub,
            proprietary: none!(),
            unknown: none!(),

            inputs: psbt_inputs,
            outputs: psbt_outputs,
        })
    }
}
