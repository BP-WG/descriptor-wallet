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

// Coding conventions
#![recursion_limit = "256"]
#![deny(dead_code, /* missing_docs, */ warnings)]

//! PSBT bitcoin library, providing all PSBT functionality from [`bitcoin`]
//! library, plus
//! - constructor, supporting miniscript-based descriptors, input descriptors,
//!   all sighash types, spendings from P2C, S2C-tweaked inputs ([`construct`]);
//! - advanced signer, supporting pre-segwit, bare and nested segwit v0, taproot
//!   key and path spendings, different forms of tweaks & commitments, all
//!   sighash types ([`sign`]);
//! - commitment-related features: managing tapret-, P2C and S2C-related
//!   proprietary keys;
//! - utility methods for fee computing, lexicographic reordering etc;
//! - command-line utility for editing PSBT data (WIP).

#[macro_use]
extern crate amplify;
#[cfg(feature = "miniscript")]
extern crate miniscript_crate as miniscript;

pub mod commit;
#[cfg(feature = "miniscript")]
pub mod construct;
#[cfg(feature = "miniscript")]
mod deduction;
pub mod iter;
pub mod lex_order;
mod proprietary;
pub mod sign;
mod types;
mod util;

pub use bitcoin::util::psbt::raw::{ProprietaryKey, ProprietaryType};
pub use bitcoin::util::psbt::{
    raw, Error, Input as InputMap, Output as OutputMap, PartiallySignedTransaction as Psbt,
    PsbtParseError,
};
pub use commit::{
    P2cOutput, TapretOutput, PSBT_IN_P2C_TWEAK, PSBT_OUT_TAPRET_COMMITMENT, PSBT_OUT_TAPRET_HOST,
    PSBT_OUT_TAPRET_PROOF, PSBT_P2C_PREFIX, PSBT_TAPRET_PREFIX,
};
#[cfg(feature = "miniscript")]
pub use deduction::{DeductionError, InputDeduce};
pub use proprietary::{
    ProprietaryKeyDescriptor, ProprietaryKeyError, ProprietaryKeyLocation, ProprietaryKeyType,
};
pub use types::{Input, Output, Terminal};
pub use util::{FeeError, InputMatchError, InputPrevout, PsbtExt};
