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

//! Library with extended support of hierarchival deterministic wallet
//! functions.
//!
//! Includes advanced derivation paths functionality and operations.

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

pub mod account;
mod derive;
mod indexes;
mod path;
mod ranges;
pub mod standards;
mod traits;
mod unsatisfiable;
mod xkey;
mod xpubref;

pub use account::TrackingAccount;
pub use derive::{DeriveDescriptor, DeriveError, DerivePatternError, DerivePublicKey, Descriptor};
pub use indexes::{
    AccountStep, HardenedIndex, HardenedIndexExpected, SegmentIndexes, TerminalStep,
    UnhardenedIndex, UnhardenedIndexExpected,
};
pub use path::DerivationSubpath;
pub use ranges::{IndexRange, IndexRangeList};
#[cfg(not(feature = "miniscript"))]
pub use standards::DescriptorType;
pub use standards::{Bip43, DerivationStandard};
pub use traits::{DerivationPathMaster, HardenedNormalSplit};
pub use unsatisfiable::UnsatisfiableKey;
pub use xkey::{
    NonStandardDerivation, XpubDescriptor, XpubOrigin, XpubParseError, XpubRequirementError,
    XpubkeyCore,
};
pub use xpubref::XpubRef;

/// Constant determining BIP32 boundary for u32 values after which index
/// is treated as hardened
pub const HARDENED_INDEX_BOUNDARY: u32 = 1 << 31;

// TODO: Replace bip32::Error with more efficient local error type
