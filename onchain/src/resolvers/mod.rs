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

//! Resolvers are traits allow accessing or computing information from a
//! bitcoin transaction graph (from blockchain, state channel, index, PSBT etc).

#[cfg(feature = "electrum")]
mod electrum;

use std::collections::{BTreeMap, HashSet};

use bitcoin::{Script, Transaction, Txid};
use bitcoin_hd::DeriveError;

use crate::blockchain::Utxo;

#[derive(Debug, Display, Error)]
#[display(doc_comments)]
/// unable to locate transaction {txid}
pub struct TxResolverError {
    /// transaction id causing the error
    pub txid: Txid,
    /// error message
    pub err: Option<Box<dyn std::error::Error>>,
}

impl TxResolverError {
    /// Convenience function for constructing resolver error from simple
    /// transaction id without error message
    #[inline]
    pub fn with(txid: Txid) -> TxResolverError { TxResolverError { txid, err: None } }
}

/// Transaction resolver
pub trait ResolveTx {
    /// Tries to find a transaction by transaction id ([`Txid`])
    fn resolve_tx(&self, txid: Txid) -> Result<Transaction, TxResolverError>;
}

/// Errors during UTXO resolution
#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum UtxoResolverError {
    /// electrum server error {0}
    #[cfg(feature = "electrum")]
    #[from]
    Electrum(electrum_client::Error),

    /// Derivation error
    #[from]
    #[display(inner)]
    Derivation(DeriveError),

    /// unable to derive descriptor for index {0} which is out of range for
    /// unhardened index derivation
    IndexOutOfRange(usize),
}

/// UTXO resolver
pub trait ResolveUtxo {
    /// Finds UTXO set for the provided address lists
    fn resolve_utxo<'script>(
        &self,
        scripts: impl IntoIterator<Item = &'script Script> + Clone,
    ) -> Result<Vec<HashSet<Utxo>>, UtxoResolverError>;

    /// Finds UTXO set for the addresses derivable from the given descriptor
    #[cfg(all(feature = "miniscript", feature = "__ignore"))]
    fn resolve_descriptor_utxo<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        descriptor: &Descriptor<DerivationAccount>,
        terminal_derivation: impl AsRef<[UnhardenedIndex]>,
        from_index: UnhardenedIndex,
        count: u32,
    ) -> Result<BTreeMap<UnhardenedIndex, (Script, HashSet<Utxo>)>, UtxoResolverError> {
        use std::cell::RefCell;
        use std::rc::Rc;

        use bitcoin::secp256k1::{Secp256k1, Verification};
        use bitcoin_hd::{
            DerivationAccount, Descriptor as BpDescriptor, SegmentIndexes, UnhardenedIndex,
        };
        use miniscript::Descriptor;

        let terminal_derivation = terminal_derivation.as_ref();
        let mut derivation = Vec::<UnhardenedIndex>::with_capacity(terminal_derivation.len() + 1);
        derivation.extend(terminal_derivation);
        derivation.push(UnhardenedIndex::zero());
        let derivation = Rc::new(RefCell::new(derivation));

        let indexes = (0..count)
            .into_iter()
            .map(|offset| {
                from_index.checked_add(offset).ok_or_else(|| {
                    UtxoResolverError::IndexOutOfRange(
                        from_index.first_index() as usize + offset as usize,
                    )
                })
            })
            .collect::<Result<Vec<_>, UtxoResolverError>>()?;

        let scripts = indexes
            .into_iter()
            .map(|index| {
                if let Some(i) = derivation.borrow_mut().last_mut() {
                    *i = index
                }
                Ok((
                    index,
                    BpDescriptor::<bitcoin::PublicKey>::script_pubkey(
                        descriptor,
                        secp,
                        &*derivation.borrow(),
                    )?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, DeriveError>>()?;

        Ok(self
            .resolve_utxo(scripts.values())?
            .into_iter()
            .zip(scripts.keys())
            .zip(scripts.values())
            .map(|((utxo_set, index), script)| (*index, (script.clone(), utxo_set)))
            .collect())
    }
}

impl ResolveTx for BTreeMap<Txid, Transaction> {
    fn resolve_tx(&self, txid: Txid) -> Result<Transaction, TxResolverError> {
        self.get(&txid)
            .cloned()
            .ok_or_else(|| TxResolverError::with(txid))
    }
}

/// Transaction resolver
pub trait ResolveTxFee {
    /// Tries to find a transaction and comput its fee by transaction id
    /// ([`Txid`])
    fn resolve_tx_fee(&self, txid: Txid) -> Result<Option<(Transaction, u64)>, TxResolverError>;
}
