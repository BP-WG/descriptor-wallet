// Bitcoin descriptor wallet library
// Written in 2019-2021 by
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

#![recursion_limit = "256"]
// Coding conventions
#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code,
    //missing_docs
)]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate amplify_derive;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate strict_encoding;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_with;
#[cfg(feature = "serde")]
extern crate serde_crate as serde;

pub mod bip32;
pub mod descriptor;
pub mod hlc;
pub mod lex_order;
pub mod psbt;
pub mod pubkey_parser;
pub mod resolvers;
mod script_types;
mod slice32;

pub use pubkey_parser::PubkeyParseError;
pub use script_types::{
    LockScript, PubkeyScript, RedeemScript, ScriptSet, SigScript, TapScript,
    ToLockScript, ToPubkeyScript, ToScripts, Witness, WitnessProgram,
    WitnessScript, WitnessVersion,
};
pub use slice32::Slice32;

use bitcoin::secp256k1;

lazy_static! {
    /// Global Secp256k1 context object
    pub static ref SECP256K1: bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All> =
        bitcoin::secp256k1::Secp256k1::new();

    pub static ref SECP256K1_PUBKEY_DUMB: bitcoin::secp256k1::PublicKey =
        bitcoin::secp256k1::PublicKey::from_secret_key(&SECP256K1, &bitcoin::secp256k1::key::ONE_KEY);
}

pub trait IntoPk {
    fn into_pk(self) -> bitcoin::PublicKey;
    fn into_legacy_pk(self) -> bitcoin::PublicKey;
}

impl IntoPk for secp256k1::PublicKey {
    fn into_pk(self) -> bitcoin::PublicKey {
        ::bitcoin::PublicKey {
            compressed: true,
            key: self,
        }
    }

    fn into_legacy_pk(self) -> bitcoin::PublicKey {
        ::bitcoin::PublicKey {
            compressed: true,
            key: self,
        }
    }
}
