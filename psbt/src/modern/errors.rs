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
/// transaction data (see [`Psbt::new`](super::Psbt::new)).
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
