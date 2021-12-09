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

use bitcoin::{Transaction, Txid};
use electrum_client::{Client, ElectrumApi, Error};

use super::{ResolveTx, ResolveTxFee, TxResolverError};

/// Electrum transaction resolver
pub struct ElectrumTxResolver {
    client: Client,
}

impl ElectrumTxResolver {
    /// Constructs new resolver with a given URL connection string (may include
    /// port number)
    pub fn new(server: &str) -> Result<Self, Error> {
        Ok(ElectrumTxResolver {
            client: Client::new(server)?,
        })
    }
}

impl ResolveTx for ElectrumTxResolver {
    fn resolve_tx(&self, txid: &Txid) -> Result<Transaction, TxResolverError> {
        self.client
            .transaction_get(txid)
            .map_err(|err| TxResolverError {
                txid: *txid,
                err: Some(Box::new(err)),
            })
    }
}

impl ResolveTxFee for ElectrumTxResolver {
    fn resolve_tx_fee(&self, txid: &Txid) -> Result<Option<(Transaction, u64)>, TxResolverError> {
        let tx = self.resolve_tx(txid)?;

        let input_amount: u64 = tx
            .input
            .iter()
            .map(|i| {
                Ok((
                    self.resolve_tx(&i.previous_output.txid)?,
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
            .ok_or_else(|| TxResolverError::with(*txid))?;

        Ok(Some((tx, fee)))
    }
}
