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

// Coding conventions
#![recursion_limit = "256"]
#![deny(dead_code, /* missing_docs, */ warnings)]

//! PSBT extensions, including enhancements related to key management

#[macro_use]
extern crate amplify;

mod proprietary;
pub mod sign;
mod structure;

pub use bitcoin::util::psbt::raw::{ProprietaryKey, ProprietaryType};
pub use bitcoin::util::psbt::{raw, Error, Input, Map, Output, PartiallySignedTransaction as Psbt};
pub use proprietary::{ProprietaryWalletInput, PSBT_WALLET_IN_TWEAK, PSBT_WALLET_PREFIX};
pub use structure::{Fee, FeeError, InputPreviousTxo, MatchError};
