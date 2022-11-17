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

//! Library for requesting and working with onchain bitcoin data: querying
//! transaction information, mining status, tracking mempool etc.

// Coding conventions
#![recursion_limit = "256"]
#![deny(dead_code, missing_docs, warnings)]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;

pub mod blockchain;
mod network;
mod resolvers;

pub use network::PublicNetwork;
pub use resolvers::{ResolveTx, ResolveTxFee, ResolveUtxo, TxResolverError, UtxoResolverError};
