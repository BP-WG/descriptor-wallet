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

use miniscript::descriptor::DescriptorType;
use miniscript::{Descriptor, MiniscriptKey};

/// Descriptor category specifies way how the `scriptPubkey` is structured
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename = "lowercase")
)]
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Display,
    Hash,
    StrictEncode,
    StrictDecode
)]
#[repr(u8)]
pub enum Category {
    /// Bare descriptors: `pk` and bare scripts, including `OP_RETURN`s.
    ///
    /// The script or public key gets right into `scriptPubkey`, i.e. as
    /// **P2PK** (for a public key) or as custom script (mostly used for
    /// `OP_RETURN`)
    #[display("bare")]
    Bare,

    /// Hash-based descriptors: `pkh` for public key hashes and BIP-16 `sh` for
    /// **P2SH** scripts.
    ///
    /// We hash public key or script and use non-SegWit `scriptPubkey`
    /// encoding, i.e. **P2PKH** or **P2SH** with corresponding non-segwit
    /// transaction input `sigScript` containing copy of [`LockScript`] in
    /// `redeemScript` field
    #[display("hashed")]
    Hashed,

    /// SegWit descriptors for legacy wallets defined in BIP 141 as P2SH nested
    /// types <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#P2WPKH_nested_in_BIP16_P2SH>:
    /// `sh(wpkh)` and `sh(wsh)`
    ///
    /// Compatibility variant for SegWit outputs when the SegWit version and
    /// program are encoded as [`RedeemScript`] in `sigScript` transaction
    /// input field, while the original public key or [`WitnessScript`] are
    /// stored in `witness`. `scriptPubkey` contains a normal **P2SH**
    /// composed agains the `redeemScript` from `sigScript`
    /// (**P2SH-P2WPKH** and **P2SH-P2WSH** variants).
    ///
    /// This type works with only with witness version v0, i.e. not applicable
    /// for Taproot.
    #[display("nested")]
    Nested,

    /// Native SegWit descriptors: `wpkh` for public keys and `wsh` for scripts
    ///
    /// We produce either **P2WPKH** or **P2WSH** output and use witness field
    /// in transaction input to store the original [`LockScript`] or the public
    /// key
    #[display("segwit")]
    SegWit,

    /// Native Taproot descriptors: `taproot`
    #[display("taproot")]
    Taproot,
}

impl<Pk> From<Descriptor<Pk>> for Category
where
    Pk: MiniscriptKey,
{
    fn from(descriptor: Descriptor<Pk>) -> Self {
        match descriptor.desc_type() {
            DescriptorType::Bare => Category::Bare,
            DescriptorType::Sh
            | DescriptorType::ShSortedMulti
            | DescriptorType::Pkh => Category::Hashed,
            DescriptorType::Wpkh
            | DescriptorType::WshSortedMulti
            | DescriptorType::Wsh => Category::SegWit,
            DescriptorType::ShWsh
            | DescriptorType::ShWpkh
            | DescriptorType::ShWshSortedMulti => Category::Nested,
        }
    }
}

impl Category {
    pub fn is_witness(self) -> bool {
        match self {
            Category::Bare | Category::Hashed => false,
            _ => true,
        }
    }
}
