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

//! Functions, errors and traits specific for PSBT constructor role.

use std::collections::BTreeSet;

use bitcoin::secp256k1::SECP256K1;
use bitcoin::util::psbt::TapTree;
use bitcoin::util::taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootBuilderError};
use bitcoin::{Script, Transaction, Txid, XOnlyPublicKey};
use bitcoin_hd::{DerivationAccount, DeriveError, SegmentIndexes, UnhardenedIndex};
use bitcoin_scripts::PubkeyScript;
use descriptors::derive::DeriveDescriptor;
use descriptors::InputDescriptor;
use miniscript::{Descriptor, ForEachKey, ToPublicKey};

use crate::{self as psbt, Psbt, PsbtVersion};

#[derive(Debug, Display, From)]
#[display(doc_comments)]
pub enum Error {
    /// unable to construct PSBT - can't resolve transaction {0}.
    ResolvingTx(Txid),

    /// unable to construct PSBT due to failing key derivetion derivation
    #[from]
    Derive(DeriveError),

    /// unable to construct PSBT due to spent transaction {0} not having
    /// referenced output #{1}
    OutputUnknown(Txid, u32),

    /// derived scriptPubkey `{3}` does not match transaction scriptPubkey
    /// `{2}` for {0}:{1}
    ScriptPubkeyMismatch(Txid, u32, Script, Script),

    /// one of PSBT outputs has invalid script data. {0}
    #[from]
    Miniscript(miniscript::Error),

    /// taproot script tree construction error. {0}
    #[from]
    TaprootBuilderError(TaprootBuilderError),

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
            Error::ResolvingTx(..) => None,
            Error::Derive(err) => Some(err),
            Error::OutputUnknown(_, _) => None,
            Error::ScriptPubkeyMismatch(_, _, _, _) => None,
            Error::Miniscript(err) => Some(err),
            Error::Inflation { .. } => None,
            Error::TaprootBuilderError(err) => Some(err),
        }
    }
}

impl Psbt {
    pub fn construct<'inputs, 'outputs>(
        descriptor: &Descriptor<DerivationAccount>,
        inputs: impl IntoIterator<Item = &'inputs InputDescriptor>,
        outputs: impl IntoIterator<Item = &'outputs (PubkeyScript, u64)>,
        change_index: impl Into<UnhardenedIndex>,
        fee: u64,
        tx_resolver: impl Fn(Txid) -> Option<Transaction>,
    ) -> Result<Psbt, Error> {
        let mut xpub = bmap! {};
        descriptor.for_each_key(|account| {
            if let Some(key_source) = account.account_key_source() {
                xpub.insert(account.account_xpub, key_source);
            }
            true
        });

        let mut total_spent = 0u64;
        let mut psbt_inputs: Vec<psbt::Input> = vec![];

        for (index, input) in inputs.into_iter().enumerate() {
            let txid = input.outpoint.txid;
            let mut tx = tx_resolver(txid).ok_or(Error::ResolvingTx(txid))?;

            // Cut out witness data
            for inp in &mut tx.input {
                inp.witness = zero!();
            }

            let prev_output = tx
                .output
                .get(input.outpoint.vout as usize)
                .ok_or(Error::OutputUnknown(txid, input.outpoint.vout))?;
            let (script_pubkey, dtype, tr_descriptor, pretr_descriptor) = match descriptor {
                Descriptor::Tr(_) => {
                    let output_descriptor = DeriveDescriptor::<XOnlyPublicKey>::derive_descriptor(
                        descriptor,
                        SECP256K1,
                        &input.terminal,
                    )?;
                    (
                        output_descriptor.script_pubkey(),
                        descriptors::CompositeDescrType::from(&output_descriptor),
                        Some(output_descriptor),
                        None,
                    )
                }
                _ => {
                    let output_descriptor =
                        DeriveDescriptor::<bitcoin::PublicKey>::derive_descriptor(
                            descriptor,
                            SECP256K1,
                            &input.terminal,
                        )?;
                    (
                        output_descriptor.script_pubkey(),
                        descriptors::CompositeDescrType::from(&output_descriptor),
                        None,
                        Some(output_descriptor),
                    )
                }
            };
            if prev_output.script_pubkey != script_pubkey {
                return Err(Error::ScriptPubkeyMismatch(
                    txid,
                    input.outpoint.vout,
                    prev_output.script_pubkey.clone(),
                    script_pubkey,
                ));
            }
            let mut bip32_derivation = bmap! {};
            let result = descriptor.for_each_key(|account| {
                match account.bip32_derivation(SECP256K1, &input.terminal) {
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

            total_spent += prev_output.value;

            let mut psbt_input = psbt::Input {
                index,
                previous_outpoint: input.outpoint,
                sequence_number: Some(input.seq_no),
                bip32_derivation,
                sighash_type: Some(input.sighash_type.into()),
                ..default!()
            };

            if dtype.is_segwit() {
                psbt_input.witness_utxo = Some(prev_output.clone());
            }
            // This is required even in case of segwit outputs, since at least Ledger Nano X
            // do not trust just `non_witness_utxo` data.
            psbt_input.non_witness_utxo = Some(tx.clone());

            if let Some(Descriptor::<XOnlyPublicKey>::Tr(tr)) = tr_descriptor {
                psbt_input.bip32_derivation.clear();
                psbt_input.tap_merkle_root = tr.spend_info().merkle_root();
                psbt_input.tap_internal_key = Some(tr.internal_key().to_x_only_pubkey());
                let spend_info = tr.spend_info();
                psbt_input.tap_scripts = spend_info
                    .as_script_map()
                    .iter()
                    .map(|((script, leaf_ver), _)| {
                        (
                            spend_info
                                .control_block(&(script.clone(), *leaf_ver))
                                .expect("taproot scriptmap is broken"),
                            (script.clone(), *leaf_ver),
                        )
                    })
                    .collect();
                if let Some(taptree) = tr.taptree() {
                    descriptor.for_each_key(|key| {
                        let (pubkey, key_source) = key
                            .bip32_derivation(SECP256K1, &input.terminal)
                            .expect("failing on second pass of the same function");
                        let pubkey = XOnlyPublicKey::from(pubkey);
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
                        .bip32_derivation(SECP256K1, &input.terminal)
                        .expect("failing on second pass of the same function");
                    let pubkey = XOnlyPublicKey::from(pubkey);
                    if pubkey == *tr.internal_key() {
                        psbt_input
                            .tap_key_origins
                            .entry(pubkey.to_x_only_pubkey())
                            .or_insert((vec![], key_source));
                    }
                    true
                });
                for (leaves, _) in psbt_input.tap_key_origins.values_mut() {
                    *leaves = leaves
                        .iter()
                        .cloned()
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect();
                }
            } else if let Some(output_descriptor) = pretr_descriptor {
                let lock_script = output_descriptor.explicit_script()?;
                if dtype.has_redeem_script() {
                    psbt_input.redeem_script = Some(lock_script.clone().into());
                }
                if dtype.has_witness_script() {
                    psbt_input.witness_script = Some(lock_script.into());
                }
            }

            psbt_inputs.push(psbt_input);
        }

        let mut total_sent = 0u64;
        let mut psbt_outputs: Vec<_> = outputs
            .into_iter()
            .enumerate()
            .map(|(index, (script, amount))| {
                total_sent += *amount;
                psbt::Output {
                    index,
                    amount: *amount,
                    script: script.clone(),
                    ..default!()
                }
            })
            .collect();

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
            let change_derivation = [UnhardenedIndex::one(), change_index.into()];
            let mut bip32_derivation = bmap! {};
            let bip32_derivation_fn = |account: &DerivationAccount| {
                let (pubkey, key_source) = account
                    .bip32_derivation(SECP256K1, change_derivation)
                    .expect("already tested descriptor derivation mismatch");
                bip32_derivation.insert(pubkey, key_source);
                true
            };

            let mut psbt_change_output = psbt::Output {
                index: psbt_outputs.len(),
                amount: change,
                ..default!()
            };
            if let Descriptor::Tr(_) = descriptor {
                let change_descriptor = DeriveDescriptor::<XOnlyPublicKey>::derive_descriptor(
                    descriptor,
                    SECP256K1,
                    change_derivation,
                )?;
                let change_descriptor = match change_descriptor {
                    Descriptor::Tr(tr) => tr,
                    _ => unreachable!(),
                };

                psbt_change_output.script = change_descriptor.script_pubkey().into();
                descriptor.for_each_key(bip32_derivation_fn);

                let internal_key: XOnlyPublicKey =
                    change_descriptor.internal_key().to_x_only_pubkey();
                psbt_change_output.tap_internal_key = Some(internal_key);
                if let Some(tree) = change_descriptor.taptree() {
                    let mut builder = TaprootBuilder::new();
                    for (depth, ms) in tree.iter() {
                        builder = builder
                            .add_leaf(depth, ms.encode())
                            .expect("insane miniscript taptree");
                    }
                    psbt_change_output.tap_tree =
                        Some(TapTree::try_from(builder).expect("non-finalized TaprootBuilder"));
                }
            } else {
                let change_descriptor = DeriveDescriptor::<bitcoin::PublicKey>::derive_descriptor(
                    descriptor,
                    SECP256K1,
                    change_derivation,
                )?;
                psbt_change_output.script = change_descriptor.script_pubkey().into();

                let dtype = descriptors::CompositeDescrType::from(&change_descriptor);
                descriptor.for_each_key(bip32_derivation_fn);

                let lock_script = change_descriptor.explicit_script()?;
                if dtype.has_redeem_script() {
                    psbt_change_output.redeem_script = Some(lock_script.clone().into());
                }
                if dtype.has_witness_script() {
                    psbt_change_output.witness_script = Some(lock_script.into());
                }
            }

            psbt_change_output.bip32_derivation = bip32_derivation;
            psbt_outputs.push(psbt_change_output);
        }

        Ok(Psbt {
            psbt_version: PsbtVersion::V0,
            tx_version: 2,
            xpub,
            inputs: psbt_inputs,
            outputs: psbt_outputs,
            fallback_locktime: None,
            proprietary: none!(),
            unknown: none!(),
        })
    }
}
