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

// In the future this mod will probably become part of bitcoin library

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
#[macro_use]
extern crate lazy_static;

mod contract;
mod deduction;
mod derive;
mod generator;
mod legacy;
mod script;
mod typesystem;

pub use contract::{CompiledMiniscript, ContractDescriptor, ContractType};
pub use deduction::{Deduce, DeductionError};
pub use derive::DeriveLockScript;
pub use generator::{Generator, GeneratorParseError};
pub use legacy::{MultiSig, SingleSig, Template};
pub use script::{
    ScriptConstruction, ScriptSource, ScriptSourceFormat, ScriptTemplate,
};
pub use typesystem::{
    Compact, ContentType, Error, Expanded, FullType, InnerType, OuterType,
    ParseError, Variants,
};
