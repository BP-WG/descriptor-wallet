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

//! Descriptor wallet library extending bitcoin & miniscript functionality.

// Coding conventions
#![recursion_limit = "256"]
#![deny(dead_code, missing_docs, warnings)]

#[cfg(feature = "miniscript")]
extern crate miniscript_crate as miniscript;
#[cfg(feature = "serde")]
extern crate serde_crate as serde;

pub extern crate bitcoin_hd as hd;
pub extern crate bitcoin_onchain as onchain;
pub extern crate bitcoin_scripts as scripts;
#[cfg(feature = "descriptors")]
pub extern crate descriptors;
pub extern crate psbt;
pub extern crate slip132;

#[cfg(feature = "cli")]
pub(crate) mod cli;

pub mod address {
    //! Address-related types for detailed payload analysis and memory-efficient
    //! processing.
    pub use scripts::address::*;
}
pub mod hlc {
    //! Hash-locked contract supporting data structures.
    pub use scripts::hlc;
}
pub mod lex_order {
    //! Lexicographic sorting functions.
    pub use psbt::lex_order;
}

#[cfg(feature = "descriptors")]
pub use descriptors::locks;
