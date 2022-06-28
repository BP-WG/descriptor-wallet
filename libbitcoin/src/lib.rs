// C library for building descriptor-based bitcoin wallets
//
// Written in 2021 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the Apache 2.0 License
// along with this software.
// If not, see <https://opensource.org/licenses/Apache-2.0>.

#![feature(try_trait_v2)]
#![deny(dead_code, /* missing_docs, */ warnings)]
#![allow(unused_unsafe)]
#![allow(clippy::missing_safety_doc)]

#[macro_use]
extern crate amplify_derive;
#[macro_use]
extern crate lazy_static;

pub mod helpers;
mod signer;

pub use signer::*;
