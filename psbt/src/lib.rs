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
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;
#[macro_use]
extern crate strict_encoding;
#[cfg(feature = "miniscript")]
extern crate miniscript_crate as miniscript;

mod errors;
mod global;
mod input;
mod output;
pub mod p2c;

#[cfg(feature = "construct")]
pub mod construct;
pub mod lex_order;
mod proprietary;
#[cfg(feature = "sign")]
pub mod sign;

pub use bitcoin::psbt::raw::ProprietaryKey;
pub use bitcoin::psbt::{raw, serialize, Error, PsbtSighashType};
pub use errors::{FeeError, InputMatchError, TxError, TxinError};
pub use global::{Psbt, PsbtParseError};
pub use input::Input;
pub use output::Output;
pub(crate) mod v0 {
    pub use bitcoin::psbt::{
        Input as InputV0, Output as OutputV0, PartiallySignedTransaction as PsbtV0,
    };
}
pub use p2c::{PSBT_IN_P2C_TWEAK, PSBT_P2C_PREFIX};
pub use proprietary::{
    ProprietaryKeyDescriptor, ProprietaryKeyError, ProprietaryKeyLocation, ProprietaryKeyType,
};

/// Version of the PSBT (V0 stands for BIP174-defined version; V2 - for BIP370).
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default)]
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
    #[default]
    V0 = 0x0,
    /// Version defined by BIP370.
    V2 = 0x2,
}
