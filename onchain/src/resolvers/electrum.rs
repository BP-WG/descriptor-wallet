// Descriptor wallet library extending bitcoin & miniscript functionality
// by LNP/BP Association (https://lnp-bp.org)
// Written in 2020-2022 by
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

use std::collections::HashSet;

use bitcoin::{Script, Transaction, Txid};
use electrum_client::{Client, ElectrumApi};

use super::{ResolveTx, ResolveTxFee, ResolveUtxo, TxResolverError, UtxoResolverError};
use crate::blockchain::Utxo;

impl ResolveTx for Client {
    fn resolve_tx(&self, txid: Txid) -> Result<Transaction, TxResolverError> {
        self.transaction_get(&txid).map_err(|err| TxResolverError {
            txid,
            err: Some(Box::new(err)),
        })
    }
}

impl ResolveTxFee for Client {
    fn resolve_tx_fee(&self, txid: Txid) -> Result<Option<(Transaction, u64)>, TxResolverError> {
        let tx = self.resolve_tx(txid)?;

        let input_amount: u64 = tx
            .input
            .iter()
            .map(|i| {
                Ok((
                    self.resolve_tx(i.previous_output.txid)?,
                    i.previous_output.vout,
                ))
            })
            .collect::<Result<Vec<_>, TxResolverError>>()?
            .into_iter()
            .map(|(tx, vout)| tx.output[vout as usize].value)
            .sum();
        let output_amount = tx.output.iter().fold(0, |sum, o| sum + o.value);
        let fee = input_amount
            .checked_sub(output_amount)
            .ok_or_else(|| TxResolverError::with(txid))?;

        Ok(Some((tx, fee)))
    }
}

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
