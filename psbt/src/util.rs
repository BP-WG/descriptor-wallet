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

use bitcoin::{Transaction, TxIn, TxOut, Txid};

use crate::{Input, Psbt};

/// Errors happening when PSBT or other resolver information does not match the
/// structure of bitcoin transaction
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error
)]
#[display(doc_comments)]
pub enum InputMatchError {
    /// no `witness_utxo` and `non_witness_utxo` is provided
    NoInputTx,

    /// provided `non_witness_utxo` does not match transaction input `prev_out`
    NoTxidMatch(Txid),

    /// spent transaction does not contain input #{0} referenced by the PSBT
    /// input
    UnmatchedInputNumber(u32),
}

/// API for accessing previous transaction output data
pub trait InputPrevout {
    /// Returns [`TxOut`] reference returned by resolver, if any, or reports
    /// specific matching error prevented from getting the output
    fn input_prevout(&self) -> Result<&TxOut, InputMatchError>;
}

/// Errors happening during fee computation
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error, From
)]
#[display(doc_comments)]
pub enum FeeError {
    /// No input source information found because of wrong or incomplete PSBT
    /// structure
    #[from]
    MatchError(InputMatchError),

    /// Sum of inputs is less than sum of outputs
    InputsLessThanOutputs,
}

/// Fee computing resolver
pub trait Fee {
    /// Returns fee for a transaction, or returns error reporting resolver
    /// problem or wrong transaction structure
    fn fee(&self) -> Result<u64, FeeError>;
}

impl InputPrevout for (&Input, &TxIn) {
    fn input_prevout(&self) -> Result<&TxOut, InputMatchError> {
        let (input, txin) = self;
        let txid = txin.previous_output.txid;
        if let Some(txout) = &input.witness_utxo {
            Ok(txout)
        } else if let Some(tx) = &input.non_witness_utxo {
            if tx.txid() != txid {
                return Err(InputMatchError::NoTxidMatch(txid));
            }
            let prev_index = txin.previous_output.vout;
            tx.output
                .get(prev_index as usize)
                .ok_or(InputMatchError::UnmatchedInputNumber(prev_index))
        } else {
            Err(InputMatchError::NoInputTx)
        }
    }
}

impl Fee for Psbt {
    fn fee(&self) -> Result<u64, FeeError> {
        let mut input_sum = 0;
        for inp in self.inputs.iter().zip(&self.unsigned_tx.input) {
            input_sum += inp.input_prevout()?.value;
        }

        let output_sum = self
            .unsigned_tx
            .output
            .iter()
            .map(|txout| txout.value)
            .sum();

        if input_sum < output_sum {
            Err(FeeError::InputsLessThanOutputs)
        } else {
            Ok(input_sum - output_sum)
        }
    }
}

/// Transaction-related PSBT extension trait
pub trait Tx {
    /// Returns transaction ID for an unsigned transaction. For SegWit
    /// transactions this is equal to the signed transaction id.
    #[inline]
    fn to_txid(&self) -> Txid {
        self.to_transaction().txid()
    }

    /// Returns transaction with empty `scriptSig` and witness
    fn to_transaction(&self) -> Transaction;
}

impl Tx for Psbt {
    #[inline]
    fn to_transaction(&self) -> Transaction {
        let mut tx = self.unsigned_tx.clone();
        for txin in &mut tx.input {
            txin.witness = Default::default();
            txin.script_sig = Default::default();
        }
        tx
    }
}
