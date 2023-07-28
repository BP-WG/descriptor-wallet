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

//! Library with extended support of hierarchival deterministic wallet
//! functions.
//!
//! Includes advanced derivation paths functionality and operations.

// Coding conventions
#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code,
    missing_docs
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[macro_use]
extern crate amplify;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;
#[cfg(feature = "miniscript")]
extern crate miniscript_crate as miniscript;

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

pub use account::DerivationAccount;
pub use derive::{DeriveError, DerivePatternError};
pub use indexes::{
    AccountStep, HardenedIndex, HardenedIndexExpected, SegmentIndexes, TerminalStep,
    UnhardenedIndex, UnhardenedIndexExpected,
};
pub use path::DerivationSubpath;
pub use ranges::{IndexRange, IndexRangeList};
pub use standards::{Bip43, DerivationStandard, DescriptorType};
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
