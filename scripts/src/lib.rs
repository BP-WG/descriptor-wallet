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

//! # Bitcoin script types
//!
//! Bitcoin doesn't make a distinction between Bitcoin script coming from
//! different sources, like *scriptPubKey* in transaction output or witness and
//! *sigScript* in transaction input. There are many other possible script
//! containers for Bitcoin script: redeem script, witness script, tapscript. In
//! fact, any "script" of [`bitcoin::Script`] type can be used for inputs and
//! outputs. What is a valid script for one will be a valid script for the
//! other; the only req. is formatting of opcodes & pushes. That would mean that
//! in principle every input script can be used as an output script, but not
//! vice versa. But really what makes a "script" is just the fact that it's
//! formatted correctly.
//!
//! While all `Script`s represent the same type **semantically**, there is a
//! clear distinction at the **logical** level: Bitcoin script has the property
//! to be committed into some other Bitcoin script – in a nested structures like
//! in several layers, like *redeemScript* inside of *sigScript* used for P2SH,
//! or *tapScript* within *witnessScript* coming from *witness* field
//! for Taproot. These nested layers do distinguish on the information they
//! contain, since some of them only commit to the hashes of the nested scripts
//! ([`bitcoin::ScriptHash`], [`WitnessProgram`]) or public keys
//! ([`bitcoin::PubkeyHash`], [`bitcoin::WPubkeyHash`]), while other contain the
//! full source of the script.
//!
//! The present type system represents a solution to the problem: it distinguish
//! different logical types by introducing `Script` wrapper types. It defines
//! [`LockScript`] as bottom layer of a script hierarchy, containing no other
//! script commitments (in form of their hashes). It also defines types above on
//! it: [`PubkeyScript`] (for whatever is there in `scriptPubkey` field of a
//! `TxOut`), [`SigScript`] (for whatever comes from `sigScript` field of
//! [`bitcoin::TxIn`]), [`RedeemScript`] and [`TapScript`]. Then, there are
//! conversion functions, which, for instance, can analyse [`PubkeyScript`] and
//! if it is a custom script or P2PK return a [`LockScript`] type - or otherwise
//! fail with error. So with this type system one is always sure which logical
//! information it does contain.
//!
//! ## Type derivation
//!
//! The following charts represent possible relations between script types:
//!
//! ```text
//!                                                                            LockScript
//!                                                                _________________________________
//!                                                                ^      ^  ^    ^                ^
//!                                                                |      |  |    |                |
//! [txout.scriptPubKey] <===> PubkeyScript --?--/P2PK & custom/---+      |  |    |                |
//!                                                                       |  |    |                |
//! [txin.sigScript] <===> SigScript --+--?!--/P2(W)PKH/--(#=PubkeyHash)--+  |    |                |
//!                                    |                                     |    |                |
//!                                    |                           (#=ScriptHash) |                |
//!                                    |                                     |    |                |
//!                                    +--?!--> RedeemScript --+--?!------/P2SH/  |                |
//!                                                            |                  |                |
//!                                                  /P2WSH-in-P2SH/  /#=V0_WitnessProgram_P2WSH/  |
//!                                                            |                  |                |
//!                                                            +--?!--> WitnessScript              |
//!                                                                       ^^      |                |
//!                                                                       || /#=V1_WitnessProgram/ |
//!                                                                       ||      |                |
//! [?txin.witness] <=====================================================++      +--?---> TapScript
//! ```
//!
//! Legend:
//! * `[source] <===> `: data source
//! * `[?source] <===> `: data source which may be absent
//! * `--+--`: algorithmic branching (alternative computation options)
//! * `--?-->`: a conversion exists, but it may fail (returns [`Option`] or
//!   [`Result`])
//! * `--?!-->`: a conversion exists, but it may fail; however one of
//!   alternative branches must always succeed
//! * `----->`: a conversion exists which can't fail
//! * `--/format/--`: a format implied by scriptPubKey program
//! * `--(#=type)--`: the hash of the value following `->` must match to the
//!   value of the `<type>`
//!
//! ## Type conversion
//!
//! ```text
//! LockScript -+-> (PubkeyScript + RedeemScript) -+-> SigScript
//!             |                                  +-> WitnessScript
//!             +-> PubkeyScript
//!             |
//!             +-> TapScript
//!
//! PubkeyScript --?--> LockScript
//! ```

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;

mod category;
mod parser;
mod types;

pub use category::Category;
pub use parser::PubkeyParseError;
pub use types::{
    LockScript, PubkeyScript, RedeemScript, ScriptSet, SigScript, TapScript, ToLockScript, ToP2pkh,
    ToPubkeyScript, ToScripts, Witness, WitnessProgram, WitnessScript,
};
