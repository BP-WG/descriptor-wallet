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

//! Resolvers are traits allow accessing or computing information from a
//! bitcoin transaction graph (from blockchain, state channel, index, PSBT etc).

#[cfg(feature = "electrum")]
mod electrum;

use std::collections::BTreeMap;

use bitcoin::{Transaction, Txid};
#[cfg(feature = "electrum")]
pub use electrum::ElectrumTxResolver;

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
pub trait TxResolver {
    /// Tries to find a transaction by transaction id ([`Txid`])
    fn resolve(&self, txid: &Txid) -> Result<Transaction, TxResolverError>;
}

impl TxResolver for BTreeMap<Txid, Transaction> {
    fn resolve(&self, txid: &Txid) -> Result<Transaction, TxResolverError> {
        self.get(txid).cloned().ok_or(TxResolverError::with(*txid))
    }
}
