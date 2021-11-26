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

use amplify::Wrapper;
use bitcoin::blockdata::script;
use bitcoin::blockdata::witness::Witness;
use bitcoin::secp256k1::{self, Secp256k1, Verification};
use bitcoin::util::address::WitnessVersion;
use bitcoin::{schnorr as bip341, Script};
use miniscript::descriptor::DescriptorType;
use miniscript::{Descriptor, MiniscriptKey, ToPublicKey};

use crate::{LockScript, PubkeyScript, RedeemScript, ScriptSet, SigScript, WitnessScript};

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

/// Errors converting to [`LockScript`] type returned by
/// [`ToLockScript::to_lock_script`].
#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error
)]
#[display(doc_comments)]
pub enum LockScriptError {
    /// attempt to generate segwit script with uncompressed pubkey {0}
    UncompressedPubkeyInWitness(bitcoin::PublicKey),

    /// taproot does not have a lock-script representation
    Taproot,
}

/// Conversion to [`LockScript`], which later may be used for creating different
/// end-point scripts, like [`PubkeyScript`], [`SigScript`], [`Witness`]
/// etc.
pub trait ToLockScript {
    /// Converts data type to [`LockScript`]. Errors on uncompressed public keys
    /// in segwit context and use of taproot, which does not have a
    /// [`LockScript`] representation (see [`LockScriptError`]).
    fn to_lock_script(&self, strategy: ConvertInfo) -> Result<LockScript, LockScriptError>;
}

/// Conversion for data types (public keys, different types of script) into
/// a `pubkeyScript` (using [`PubkeyScript`] type) using particular conversion
/// [`Category`]
pub trait ToPubkeyScript {
    /// Converts data type to [`PubkeyScript`]. Returns `None` if the conversion
    /// is applied to uncompressed public key in segwit context.
    fn to_pubkey_script(&self, strategy: ConvertInfo) -> Option<PubkeyScript>;
}

/// Script set generation from public keys or a given [`LockScript`] (with
/// [`TapScript`] support planned for the future).
pub trait ToScripts
where
    Self: ToPubkeyScript,
{
    fn to_scripts(&self, strategy: ConvertInfo) -> Option<ScriptSet> {
        Some(ScriptSet {
            pubkey_script: self.to_pubkey_script(strategy)?,
            sig_script: self.to_sig_script(strategy)?,
            witness: self.to_witness(strategy),
        })
    }
    fn to_sig_script(&self, strategy: ConvertInfo) -> Option<SigScript>;
    fn to_witness(&self, strategy: ConvertInfo) -> Option<Witness>;
}

impl ToPubkeyScript for WitnessScript {
    /// Never returns [`None`]
    fn to_pubkey_script(&self, strategy: ConvertInfo) -> Option<PubkeyScript> {
        LockScript::from(self.clone()).to_pubkey_script(strategy)
    }
}

impl ToPubkeyScript for RedeemScript {
    /// Never returns [`None`]
    fn to_pubkey_script(&self, strategy: ConvertInfo) -> Option<PubkeyScript> {
        LockScript::from(self.clone()).to_pubkey_script(strategy)
    }
}

impl ToPubkeyScript for LockScript {
    /// Never returns [`None`]
    fn to_pubkey_script(&self, strategy: ConvertInfo) -> Option<PubkeyScript> {
        Some(match strategy {
            ConvertInfo::Bare => self.to_inner().into(),
            ConvertInfo::Hashed => Script::new_p2sh(&self.script_hash()).into(),
            ConvertInfo::SegWitV0 => Script::new_v0_p2wsh(&self.wscript_hash()).into(),
            ConvertInfo::NestedV0 => {
                let redeem_script =
                    LockScript::from(self.to_pubkey_script(ConvertInfo::SegWitV0)?.to_inner());
                Script::new_p2sh(&redeem_script.script_hash()).into()
            }
            ConvertInfo::Taproot { output_key } => {
                Script::new_witness_program(WitnessVersion::V1, &output_key.serialize()).into()
            }
        })
    }
}

impl ToScripts for LockScript {
    fn to_sig_script(&self, strategy: ConvertInfo) -> Option<SigScript> {
        Some(match strategy {
            // sigScript must contain just a plain signatures, which will be
            // added later
            ConvertInfo::Bare => SigScript::default(),
            ConvertInfo::Hashed => script::Builder::new()
                .push_slice(WitnessScript::from(self.clone()).as_bytes())
                .into_script()
                .into(),
            ConvertInfo::NestedV0 => {
                // Here we support only V0 version, since V1 version can't
                // be generated from `LockScript` and will require
                // `TapScript` source
                let redeem_script =
                    LockScript::from(self.to_pubkey_script(ConvertInfo::SegWitV0)?.to_inner());
                script::Builder::new()
                    .push_slice(redeem_script.as_bytes())
                    .into_script()
                    .into()
            }
            // For any segwit version the sigScript must be empty (with the
            // exception to the case of P2SH-embedded outputs, which is already
            // covered above
            _ => SigScript::default(),
        })
    }

    fn to_witness(&self, strategy: ConvertInfo) -> Option<Witness> {
        match strategy {
            ConvertInfo::Bare | ConvertInfo::Hashed => None,
            ConvertInfo::SegWitV0 | ConvertInfo::NestedV0 => {
                let witness_script = WitnessScript::from(self.clone());
                Some(Witness::from(vec![witness_script.to_bytes()]))
            }
            ConvertInfo::Taproot { .. } => None,
        }
    }
}

impl ToLockScript for bitcoin::PublicKey {
    fn to_lock_script(&self, strategy: ConvertInfo) -> Result<LockScript, LockScriptError> {
        Ok(match strategy {
            ConvertInfo::Bare => Script::new_p2pk(self),
            ConvertInfo::Hashed => Script::new_p2pkh(&self.pubkey_hash()),
            ConvertInfo::SegWitV0 => Script::new_v0_p2wpkh(
                &self
                    .wpubkey_hash()
                    .ok_or(LockScriptError::UncompressedPubkeyInWitness(*self))?,
            ),
            ConvertInfo::NestedV0 => {
                let redeem_script = self
                    .to_pubkey_script(ConvertInfo::SegWitV0)
                    .ok_or(LockScriptError::UncompressedPubkeyInWitness(*self))?;
                Script::new_p2sh(&redeem_script.script_hash())
            }
            ConvertInfo::Taproot { .. } => return Err(LockScriptError::Taproot),
        }
        .into())
    }
}

impl ToPubkeyScript for bitcoin::PublicKey {
    fn to_pubkey_script(&self, strategy: ConvertInfo) -> Option<PubkeyScript> {
        Some(
            match strategy {
                ConvertInfo::Bare => Script::new_p2pk(self),
                ConvertInfo::Hashed => Script::new_p2pkh(&self.pubkey_hash()),
                ConvertInfo::SegWitV0 => Script::new_v0_p2wpkh(&self.wpubkey_hash()?),
                ConvertInfo::NestedV0 => {
                    let redeem_script = self.to_pubkey_script(ConvertInfo::SegWitV0)?;
                    Script::new_p2sh(&redeem_script.script_hash())
                }
                ConvertInfo::Taproot { output_key } => {
                    Script::new_witness_program(WitnessVersion::V1, &output_key.serialize())
                }
            }
            .into(),
        )
    }
}

impl ToScripts for bitcoin::PublicKey {
    fn to_sig_script(&self, strategy: ConvertInfo) -> Option<SigScript> {
        Some(match strategy {
            // sigScript must contain just a plain signatures, which will be
            // added later
            ConvertInfo::Bare => SigScript::default(),
            ConvertInfo::Hashed => script::Builder::new()
                .push_slice(&self.to_bytes())
                .into_script()
                .into(),
            ConvertInfo::NestedV0 => {
                let redeem_script =
                    LockScript::from(self.to_pubkey_script(ConvertInfo::SegWitV0)?.into_inner());
                script::Builder::new()
                    .push_slice(redeem_script.as_bytes())
                    .into_script()
                    .into()
            }
            // For any segwit version the sigScript must be empty (with the
            // exception to the case of P2SH-embedded outputs, which is already
            // covered above
            _ => SigScript::default(),
        })
    }

    fn to_witness(&self, strategy: ConvertInfo) -> Option<Witness> {
        match strategy {
            ConvertInfo::Bare | ConvertInfo::Hashed => None,
            ConvertInfo::SegWitV0 | ConvertInfo::NestedV0 => {
                Some(Witness::from(vec![self.to_bytes()]))
            }
            ConvertInfo::Taproot { .. } => None,
        }
    }
}

impl ToLockScript for secp256k1::PublicKey {
    #[inline]
    fn to_lock_script(&self, strategy: ConvertInfo) -> Result<LockScript, LockScriptError> {
        bitcoin::PublicKey {
            compressed: true,
            key: *self,
        }
        .to_lock_script(strategy)
    }
}

impl ToPubkeyScript for secp256k1::PublicKey {
    fn to_pubkey_script(&self, strategy: ConvertInfo) -> Option<PubkeyScript> {
        Some(self.to_lock_script(strategy).ok()?.into_inner().into())
    }
}

impl ToScripts for secp256k1::PublicKey {
    #[inline]
    fn to_sig_script(&self, strategy: ConvertInfo) -> Option<SigScript> {
        bitcoin::PublicKey {
            compressed: true,
            key: *self,
        }
        .to_sig_script(strategy)
    }

    #[inline]
    fn to_witness(&self, strategy: ConvertInfo) -> Option<Witness> {
        bitcoin::PublicKey {
            compressed: true,
            key: *self,
        }
        .to_witness(strategy)
    }
}

pub trait ToP2pkh {
    fn to_p2pkh(&self) -> Option<PubkeyScript>;
    fn to_p2wpkh(&self) -> Option<PubkeyScript>;
    fn to_p2sh_wpkh(&self) -> Option<PubkeyScript>;
}

impl<T> ToP2pkh for T
where
    T: ToPublicKey,
{
    fn to_p2pkh(&self) -> Option<PubkeyScript> {
        self.to_public_key().to_pubkey_script(ConvertInfo::Hashed)
    }

    fn to_p2wpkh(&self) -> Option<PubkeyScript> {
        self.to_public_key().to_pubkey_script(ConvertInfo::SegWitV0)
    }

    fn to_p2sh_wpkh(&self) -> Option<PubkeyScript> {
        self.to_public_key().to_pubkey_script(ConvertInfo::NestedV0)
    }
}
