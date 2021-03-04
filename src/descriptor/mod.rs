// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

//! General workflow for working with ScriptPubkey* types:
//! ```text
//! Template -> Descriptor -> Structure -> PubkeyScript -> TxOut
//!
//! TxOut -> PubkeyScript -> Descriptor -> Structure -> Format
//! ```

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
    Category, Compact, ContentType, Error, Expanded, FullType, InnerType,
    OuterType, ParseError, Variants,
};
