// BP foundation libraries Bitcoin crates implementing the foundations of
// Bitcoin protocol by LNP/BP Association (https://lnp-bp.org)
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
#![deny(dead_code, missing_docs, warnings)]

//! # Bitcoin script types
//!
//! Bitcoin doesn't make a distinction between Bitcoin script coming from
//! different sources, like *scriptPubKey* in transaction output or *witness*
//! and *scriptSig* in transaction input. There are many other possible script
//! containers for Bitcoin script: redeem script, witness script, taproot leaf
//! scripts of different versions. In fact, any "script" of
//! [`bitcoin::Script`] type can be used for inputs and outputs. What is a valid
//! script for in one context will not be a valid script for some other. That
//! would mean that in principle with existing [`bitcoin::Script`] type every
//! input script can be used as an output script, leading to potentially harmful
//! code coming from an unaware developer.
//!
//! While all [`bitcoin::Script`]s have the same parsing rules converting byte
//! string into a set of instructions (i.e. the same **syntax**), there are
//! multiple ways how the consensus meaning of these instructions will be
//! interpreted under different contexts (different **semantics**). Moreover,
//! the scripts may be nested - or to be committed into some other
//! Bitcoin script – in a nested structures like in several layers, like
//! *redeemScript* inside of *scriptSig* used for P2SH, or *tapScript* within
//! *witnessScript* coming from *witness* field for Taproot. These nested layers
//! do distinguish on the information they contain, since some of them only
//! commit to the hashes of the nested scripts ([`bitcoin::ScriptHash`],
//! [`WitnessProgram`]) or public keys ([`bitcoin::PubkeyHash`],
//! [`bitcoin::WPubkeyHash`]), while other contain the full source of the
//! script.
//!
//! The present type system represents a solution to the problem: it distinguish
//! different logical types by introducing `Script` wrapper types. It defines
//! [`LockScript`] as bottom layer of a script, containing no other script
//! commitments (in form of their hashes). It also defines types above on it:
//! [`PubkeyScript`] (for whatever is there in `scriptPubkey` field
//! of a [`bitcoin::TxOut`]), [`SigScript`] (for whatever comes from `scriptSig`
//! field of [`bitcoin::TxIn`]), [`RedeemScript`] and [`WitnessScript`].
//! For taproot, we define [`LeafScript`] as a top level of specific script
//! branch (see [`bitcoin::util::psbt::TapTree`]) and [`crate::TapScript`] as a
//! type specific for the current `0xC0` tapleaf version semantics, defined in
//! BIP-342.
//!
//! There are conversion functions, which, for instance, can analyse
//! [`PubkeyScript`] and if it is a custom script or P2PK return a
//! [`LockScript`] type - or otherwise fail with error. These conversions
//! functions reside in [`convert`] module. So with this type system one is
//! always sure which semantic information it does contain.
//!
//! ## Type conversion
//!
//! ```text
//! LockScript -+-> (PubkeyScript + RedeemScript) -+-> SigScript
//!             |                                  +-> WitnessScript
//!             +-> PubkeyScript
//!             |
//! TapScript ----> LeafScript
//!
//! PubkeyScript --?--> LockScript
//! ```

#[macro_use]
extern crate amplify;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;

pub mod address;
pub mod convert;
pub mod hlc;
pub mod taproot;
mod types;

pub use convert::ConvertInfo;
#[cfg(feature = "miniscript")]
pub use parser::PubkeyParseError;
pub use types::{
    IntoNodeHash, LeafScript, LockScript, PubkeyScript, RedeemScript, ScriptCode, ScriptSet,
    SigScript, TapNodeHash, TapScript, TaprootWitness, TaprootWitnessError, WitnessProgram,
    WitnessScript,
};
