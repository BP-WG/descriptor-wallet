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
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;
#[macro_use]
extern crate strict_encoding;

mod errors;
mod global;
mod input;
mod output;

pub mod commit;
#[cfg(feature = "miniscript")]
pub mod construct;
mod proprietary;
#[cfg(feature = "sign")]
pub mod sign;
mod util;

pub use bitcoin::psbt::{raw, serialize, Error, PsbtParseError, PsbtSighashType};
pub use errors::{FeeError, InputMatchError, TxError, TxinError};
pub use global::Psbt;
pub use input::Input;
pub use output::Output;
pub(crate) mod v0 {
    pub use bitcoin::psbt::{
        Input as InputV0, Output as OutputV0, PartiallySignedTransaction as PsbtV0,
    };
}
pub use commit::{
    P2cOutput, PSBT_IN_P2C_TWEAK, PSBT_OUT_TAPRET_COMMITMENT, PSBT_OUT_TAPRET_HOST,
    PSBT_OUT_TAPRET_PROOF, PSBT_P2C_PREFIX, PSBT_TAPRET_PREFIX,
};
pub use proprietary::{
    ProprietaryKeyDescriptor, ProprietaryKeyError, ProprietaryKeyLocation, ProprietaryKeyType,
};
pub use util::lex_order;
#[cfg(feature = "miniscript")]
pub use util::DeductionError;

/// Version of the PSBT (V0 stands for BIP174-defined version; V2 - for BIP370).
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictEncode, StrictDecode)]
#[strict_encoding(repr = u32)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[repr(u32)]
pub enum PsbtVersion {
    /// Version defined by BIP174.
    V0 = 0x0,
    /// Version defined by BIP370.
    V2 = 0x2,
}

impl Default for PsbtVersion {
    fn default() -> Self { PsbtVersion::V2 }
}
