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
#[cfg(feature = "miniscript_descriptors")]
pub use resolvers::ResolveDescriptor;
pub use resolvers::{ResolveTx, ResolveTxFee, ResolveUtxo, TxResolverError, UtxoResolverError};
