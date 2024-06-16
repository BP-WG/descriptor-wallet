// Wallet-level libraries for bitcoin protocol by LNP/BP Association
//
// Written in 2020-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// This software is distributed without any warranty.
//
// You should have received a copy of the Apache-2.0 License
// along with this software.
// If not, see <https://opensource.org/licenses/Apache-2.0>.

use std::collections::HashSet;

use bitcoin::Script;
use electrum_client::{Client, ElectrumApi};

use super::{ResolveUtxo, UtxoResolverError};
use crate::blockchain::Utxo;

impl ResolveUtxo for Client {
    fn resolve_utxo<'script>(
        &self,
        scripts: impl IntoIterator<Item = &'script Script> + Clone,
    ) -> Result<Vec<HashSet<Utxo>>, UtxoResolverError> {
        Ok(self
            .batch_script_list_unspent(scripts)?
            .into_iter()
            .map(|res| res.into_iter().map(Utxo::from).collect())
            .collect())
    }
}
