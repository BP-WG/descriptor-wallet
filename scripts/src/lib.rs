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

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;

mod category;
mod parser;
mod types;

pub use category::Category;
pub use parser::PubkeyParseError;
pub use types::{
    LockScript, PubkeyScript, RedeemScript, ScriptSet, SigScript, TapScript,
    ToLockScript, ToP2pkh, ToPubkeyScript, ToScripts, Witness, WitnessProgram,
    WitnessScript, WitnessVersion, WitnessVersionError,
};
