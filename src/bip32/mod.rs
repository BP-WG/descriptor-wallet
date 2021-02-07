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

mod components;
mod path;
mod pubkeychain;
mod range;
mod traits;
mod xpubref;

pub use components::{ComponentsParseError, DerivationComponents};
pub use path::{
    BranchStep, ChildIndex, HardenedIndex, TerminalStep, UnhardenedIndex,
};
pub use pubkeychain::PubkeyChain;
pub use range::{DerivationRange, DerivationRangeVec};
pub use traits::{DerivationPathMaster, DerivePublicKey, HardenedNormalSplit};
pub use xpubref::XpubRef;

/// Constant determining BIP32 boundary for u32 values after which index
/// is treated as hardened
pub const HARDENED_INDEX_BOUNDARY: u32 = 1 << 31;
