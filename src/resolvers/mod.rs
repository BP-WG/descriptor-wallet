// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2019 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

//! Resolvers are traits allow accessing or computing information from a
//! bitcoin transaction graph (from blockchain, state channel, index, PSBT etc).

#[cfg(feature = "electrum")]
mod electrum;
#[cfg(feature = "electrum")]
pub use electrum::ElectrumTxResolver;

use bitcoin::{Transaction, Txid};

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
