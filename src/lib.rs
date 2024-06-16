// Descriptor wallet library extending bitcoin & miniscript functionality
// by LNP/BP Association (https://lnp-bp.org)
// Written in 2020-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the Apache-2.0 License
// along with this software.
// If not, see <https://opensource.org/licenses/Apache-2.0>.

//! Descriptor wallet library extending bitcoin & miniscript functionality.

// Coding conventions
#![recursion_limit = "256"]
#![deny(dead_code, missing_docs, warnings)]

#[macro_use]
extern crate amplify;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;
#[cfg(feature = "miniscript")]
extern crate miniscript_crate as miniscript;

pub extern crate bitcoin_hd as hd;
pub extern crate descriptors;
pub extern crate psbt;
pub extern crate slip132;

pub mod blockchain;
mod network;
mod resolvers;

#[cfg(feature = "cli")]
pub(crate) mod cli;

pub use network::PublicNetwork;
#[cfg(feature = "miniscript")]
pub use resolvers::ResolveDescriptor;
pub use resolvers::{ResolveTxFee, ResolveUtxo, UtxoResolverError};

pub mod lex_order {
    //! Lexicographic sorting functions.
    #[deprecated(since = "0.6.1", note = "Use `wallet::lex_order` instead")]
    pub use psbt::lex_order;
    pub use psbt::lex_order::*;
}
