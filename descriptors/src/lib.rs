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

//! General workflow for working with ScriptPubkey* types:
//! ```text
//! Template -> Descriptor -> Structure -> PubkeyScript -> TxOut
//!
//! TxOut -> PubkeyScript -> Descriptor -> Structure -> Format
//! ```

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;

mod descriptor;
mod input;
#[cfg(feature = "miniscript")]
mod templates;
mod deduction;
pub mod derive;

pub use descriptor::{
    BareDescriptor, CompositeDescrType, DescriptorClass, DescrVariants, Error, InnerDescrType,
    OuterDescrType, ParseError, ScriptPubkeyDescr, SpkClass, UnsupportedScriptPubkey,
};
pub use input::InputDescriptor;
#[cfg(feature = "miniscript")]
pub use templates::ScriptTemplate;
pub use deduction::DeductionError;
