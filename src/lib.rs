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
extern crate strict_encoding;
#[macro_use]
extern crate lightning_encoding;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_with;
#[cfg(feature = "serde")]
extern crate serde_crate as serde;

pub extern crate bitcoin_hd as hd;
pub extern crate bitcoin_onchain as onchain;
pub extern crate bitcoin_scripts as scripts;
#[cfg(feature = "descriptors")]
pub extern crate descriptors;
pub extern crate psbt;

pub mod address;
pub mod hlc;
pub mod lex_order;

use bitcoin::secp256k1;
#[cfg(feature = "descriptors")]
pub use descriptors::locks;
#[deprecated(note = "Use `wallet::hd` instead")]
pub use hd as bitcoin_hd;

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
