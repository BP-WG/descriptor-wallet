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

use bitcoin::schnorr as bip341;
use bitcoin::secp256k1::{Secp256k1, Verification};
use miniscript::descriptor::DescriptorType;
use miniscript::{Descriptor, MiniscriptKey, ToPublicKey};

/// Descriptor category specifies way how the `scriptPubkey` is structured
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Display, Hash)]
#[repr(u8)]
pub enum ConvertInfo {
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
    /// transaction input `sigScript` containing copy of [`crate::LockScript`]
    /// in `redeemScript` field
    #[display("hashed")]
    Hashed,

    /// SegWit descriptors for legacy wallets defined in BIP 141 as P2SH nested
    /// types <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#P2WPKH_nested_in_BIP16_P2SH>:
    /// `sh(wpkh)` and `sh(wsh)`
    ///
    /// Compatibility variant for SegWit outputs when the SegWit version and
    /// program are encoded as [`crate::RedeemScript`] in `sigScript`
    /// transaction input field, while the original public key or
    /// [`crate::WitnessScript`] are stored in `witness`. `scriptPubkey`
    /// contains a normal **P2SH** composed agains the `redeemScript` from
    /// `sigScript` (**P2SH-P2WPKH** and **P2SH-P2WSH** variants).
    ///
    /// This type works with only with witness version v0, i.e. not applicable
    /// for Taproot.
    #[display("nested")]
    NestedV0,

    /// Native SegWit descriptors: `wpkh` for public keys and `wsh` for scripts
    ///
    /// We produce either **P2WPKH** or **P2WSH** output and use witness field
    /// in transaction input to store the original [`crate::LockScript`] or the
    /// public key
    #[display("segwit")]
    SegWitV0,

    /// Native Taproot descriptors: `taproot`
    #[display("taproot")]
    Taproot {
        output_key: bip341::TweakedPublicKey,
    },
}

impl ConvertInfo {
    pub fn with_descriptor<Pk, Ctx>(secp: &Secp256k1<Ctx>, descriptor: &Descriptor<Pk>) -> Self
    where
        Pk: MiniscriptKey + ToPublicKey,
        Ctx: Verification,
    {
        match (descriptor.desc_type(), descriptor) {
            (DescriptorType::Bare, _) => ConvertInfo::Bare,
            (DescriptorType::Sh | DescriptorType::ShSortedMulti | DescriptorType::Pkh, _) => {
                ConvertInfo::Hashed
            }
            (DescriptorType::Wpkh | DescriptorType::WshSortedMulti | DescriptorType::Wsh, _) => {
                ConvertInfo::SegWitV0
            }
            (
                DescriptorType::ShWsh | DescriptorType::ShWpkh | DescriptorType::ShWshSortedMulti,
                _,
            ) => ConvertInfo::NestedV0,
            (_, Descriptor::Tr(tr)) => {
                let mut tr = tr.clone();
                ConvertInfo::Taproot {
                    output_key: bip341::TweakedPublicKey::dangerous_assume_tweaked(
                        tr.spend_info(secp).output_key(),
                    ),
                }
            }
            _ => unreachable!("taproot descriptor type for non-taproot descriptor"),
        }
    }
}

impl ConvertInfo {
    /// Detects whether descriptor is a non-nested segwit
    #[inline]
    pub fn is_segwit(self) -> bool { !matches!(self, ConvertInfo::Bare | ConvertInfo::Hashed) }

    #[inline]
    pub fn is_taproot(self) -> bool { !matches!(self, ConvertInfo::Taproot { .. }) }
}
