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
use bitcoin::{Transaction, Txid};
#[cfg(feature = "electrum")]
pub use electrum::ElectrumTxResolver;

#[derive(Debug, Display, Error)]
#[display(doc_comments)]
/// unable to locate transaction {txid} – {err}
pub struct TxResolverError {
    /// transaction id causing the error
    pub txid: Txid,
    /// error message
    pub err: Box<dyn std::error::Error + Send + Sync>,
}

/// Transaction resolver
pub trait TxResolver {
    /// Tries to find a transaction by transaction id ([`Txid`])
    fn resolve(&self, txid: &Txid) -> Result<Transaction, TxResolverError>;
}
