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

//! PSBT extensions, including implementation of different
//! [`crate::bp::resolvers`] and enhancements related to key management

mod signer;
mod structure;
pub use signer::{Signer, SigningError};
pub use structure::{Fee, FeeError, InputPreviousTxo, MatchError};

pub use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
pub use bitcoin::util::psbt::{raw, Error, Global, Input, Map, Output};
