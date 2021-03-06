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

// In the future this mod will probably become part of Miniscript library

mod parser;
mod types;

pub use parser::PubkeyParseError;
pub use types::{
    LockScript, PubkeyScript, RedeemScript, ScriptSet, SigScript, TapScript,
    ToLockScript, ToP2pkh, ToPubkeyScript, ToScripts, Witness, WitnessProgram,
    WitnessScript, WitnessVersion, WitnessVersionError,
};
