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

use bitcoin::Txid;

/// Errors during [`Input`](super::Input) construction from an unsigned
/// transaction input (see [`Input::new`](super::Input::new)).
#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error
)]
#[display(doc_comments)]
pub enum TxinError {
    /// the scriptSigs in the {0} unsigned transaction output is not empty.
    UnsignedTxHasScriptSigs(usize),

    /// the scriptWitnesses in the {0} unsigned transaction output is not empty.
    UnsignedTxHasScriptWitnesses(usize),
}

/// Errors during [`Psbt`](super::Psbt) construction from an unsigned
/// transaction data (see [`Psbt::with`](super::Psbt::with())).
#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error, From
)]
pub enum TxError {
    /// Error in an unsigned transaction input (see [`TxinError`]).
    #[from]
    #[display(inner)]
    Txin(TxinError),

    /// the unsigned transaction has negative version value ({0}), which is not
    /// allowed in PSBT.
    InvalidTxVersion(i32),
}

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
