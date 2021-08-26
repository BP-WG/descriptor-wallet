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

#[derive(Clone, Copy, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
#[cfg_attr(feature = "electrum", from(electrum_client::Error))]
/// Error resolving transaction
pub struct TxResolverError;

pub trait TxResolver {
    fn resolve(
        &self,
        txid: &Txid,
    ) -> Result<Option<(Transaction, u64)>, TxResolverError>;
}
