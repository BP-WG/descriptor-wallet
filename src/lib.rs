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

// Coding conventions
#![recursion_limit = "256"]
#![deny(dead_code, /* missing_docs, */ warnings)]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate strict_encoding;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_with;
#[cfg(feature = "serde")]
extern crate serde_crate as serde;

pub extern crate bitcoin_scripts as scripts;
#[cfg(feature = "descriptors")]
pub extern crate descriptors;
pub extern crate hdw;
pub extern crate psbt;

mod address;
pub mod blockchain;
mod hlc;
mod lex_order;
pub mod resolvers;

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
