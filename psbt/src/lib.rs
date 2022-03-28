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

//! PSBT extensions, including enhancements related to key management

#[macro_use]
extern crate amplify;
#[cfg(feature = "miniscript")]
extern crate miniscript_crate as miniscript;

#[cfg(feature = "miniscript")]
pub mod construct;
#[cfg(feature = "miniscript")]
mod deduction;
pub mod lex_order;
mod proprietary;
pub mod sign;
mod util;

pub use bitcoin::util::psbt::raw::{ProprietaryKey, ProprietaryType};
pub use bitcoin::util::psbt::{
    raw, Error, Input, Output, PartiallySignedTransaction as Psbt, PsbtParseError,
};
#[cfg(feature = "miniscript")]
pub use deduction::{DeductionError, InputDeduce};
pub use proprietary::{
    InputP2cTweak, PSBT_IN_P2C_TWEAK, PSBT_LNPBP_CAN_HOST_COMMITMENT, PSBT_LNPBP_PREFIX,
    PSBT_P2C_PREFIX,
};
pub use util::{Fee, FeeError, InputMatchError, InputPrevout, Tx};
