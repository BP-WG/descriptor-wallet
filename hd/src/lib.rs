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

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;
#[macro_use]
extern crate lazy_static;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;

mod components;
mod path;
mod pubkeychain;
mod range;
mod traits;
mod xpubref;

pub use components::{ComponentsParseError, DerivationComponents};
pub use path::{
    BranchStep, ChildIndex, HardenedIndex, TerminalStep, UnhardenedIndex,
};
pub use pubkeychain::PubkeyChain;
pub use range::{DerivationRange, DerivationRangeVec};
pub use traits::{DerivationPathMaster, DerivePublicKey, HardenedNormalSplit};
pub use xpubref::XpubRef;

/// Constant determining BIP32 boundary for u32 values after which index
/// is treated as hardened
pub const HARDENED_INDEX_BOUNDARY: u32 = 1 << 31;
