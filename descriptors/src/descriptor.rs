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

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use bitcoin::schnorr::UntweakedPublicKey;
use bitcoin::secp256k1::{self, Secp256k1, Verification};
use bitcoin::util::taproot::TapBranchHash;
use bitcoin::Script;
use bitcoin_scripts::convert::{LockScriptError, ToPubkeyScript};
use bitcoin_scripts::{ConvertInfo, PubkeyScript, RedeemScript, WitnessScript};
use miniscript::descriptor::DescriptorType;
use miniscript::policy::compiler::CompilerError;
use miniscript::{Descriptor, MiniscriptKey, Terminal};

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[repr(u8)]
pub enum ContentType {
    #[display("bare")]
    Bare,

    #[display("hashed")]
    Hashed,

    #[display("segwit")]
    SegWit,

    #[display("taproot")]
    Taproot,
}

impl ContentType {
    pub fn into_inner_type(self, script: bool) -> InnerType {
        match (self, script) {
            (ContentType::Bare, false) => InnerType::Pk,
            (ContentType::Hashed, false) => InnerType::Pk,
            (ContentType::SegWit, false) => InnerType::Wpkh,

            (ContentType::Bare, true) => InnerType::Bare,
            (ContentType::Hashed, true) => InnerType::Sh,
            (ContentType::SegWit, true) => InnerType::Wsh,

            (ContentType::Taproot, _) => InnerType::Tr,
        }
    }

    pub fn into_simple_outer_type(self, script: bool) -> OuterType {
        match (self, script) {
            (ContentType::Bare, false) => OuterType::Pk,
            (ContentType::Hashed, false) => OuterType::Pk,
            (ContentType::SegWit, false) => OuterType::Wpkh,

            (ContentType::Bare, true) => OuterType::Bare,
            (ContentType::Hashed, true) => OuterType::Sh,
            (ContentType::SegWit, true) => OuterType::Wsh,

            (ContentType::Taproot, _) => OuterType::Tr,
        }
    }

    pub fn into_nested_outer_type(self, script: bool) -> OuterType {
        match (self, script) {
            (ContentType::Bare, false) => OuterType::Pk,
            (ContentType::Hashed, false) => OuterType::Pk,
            (ContentType::SegWit, false) => OuterType::Sh,

            (ContentType::Bare, true) => OuterType::Bare,
            (ContentType::Hashed, true) => OuterType::Sh,
            (ContentType::SegWit, true) => OuterType::Sh,

            (ContentType::Taproot, _) => OuterType::Tr,
        }
    }
}

impl From<FullType> for ContentType {
    fn from(full: FullType) -> Self {
        match full {
            FullType::Bare | FullType::Pk => ContentType::Bare,
            FullType::Pkh | FullType::Sh => ContentType::Hashed,
            FullType::Wpkh | FullType::Wsh | FullType::ShWpkh | FullType::ShWsh => {
                ContentType::SegWit
            }
            FullType::Tr => ContentType::Taproot,
        }
    }
}

impl From<ConvertInfo> for ContentType {
    fn from(category: ConvertInfo) -> Self {
        match category {
            ConvertInfo::Bare => ContentType::Bare,
            ConvertInfo::Hashed => ContentType::Hashed,
            ConvertInfo::NestedV0 | ConvertInfo::SegWitV0 => ContentType::SegWit,
            ConvertInfo::Taproot { .. } => ContentType::Taproot,
        }
    }
}

impl Default for ContentType {
    fn default() -> Self { ContentType::SegWit }
}

impl FromStr for ContentType {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().trim() {
            "bare" | "pk" => ContentType::Bare,
            "hashed" | "pkh" | "sh" => ContentType::Hashed,
            "segwit" | "wsh" | "shwsh" | "wpkh" | "shwpkh" => ContentType::SegWit,
            "taproot" | "tr" => ContentType::Taproot,
            unknown => return Err(ParseError::UnrecognizedDescriptorName(unknown.to_owned())),
        })
    }
}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[repr(u8)]
pub enum FullType {
    #[display("bare")]
    Bare,

    #[display("pk")]
    Pk,

    #[display("pkh")]
    Pkh,

    #[display("sh")]
    Sh,

    #[display("wpkh")]
    Wpkh,

    #[display("wsh")]
    Wsh,

    #[display("shWpkh")]
    ShWpkh,

    #[display("shWsh")]
    ShWsh,

    #[display("tr")]
    Tr,
}

impl FullType {
    pub fn outer_category(self) -> ContentType {
        match self {
            FullType::Bare | FullType::Pk => ContentType::Bare,
            FullType::Pkh | FullType::Sh => ContentType::Hashed,
            FullType::Wpkh | FullType::Wsh => ContentType::SegWit,
            FullType::ShWpkh | FullType::ShWsh => ContentType::Hashed,
            FullType::Tr => ContentType::Taproot,
        }
    }

    pub fn inner_category(self) -> ContentType {
        match self {
            FullType::Bare | FullType::Pk => ContentType::Bare,
            FullType::Pkh | FullType::Sh => ContentType::Hashed,
            FullType::Wpkh | FullType::Wsh => ContentType::SegWit,
            FullType::ShWpkh | FullType::ShWsh => ContentType::SegWit,
            FullType::Tr => ContentType::Taproot,
        }
    }

    #[inline]
    pub fn is_segwit(self) -> bool { self.inner_category() == ContentType::SegWit }

    #[inline]
    pub fn is_taproot(self) -> bool { self == FullType::Tr }

    #[inline]
    pub fn has_redeem_script(self) -> bool {
        matches!(self, FullType::ShWsh | FullType::ShWpkh | FullType::Sh)
    }

    #[inline]
    pub fn has_witness_script(self) -> bool {
        self.is_segwit() && !self.is_taproot() && !matches!(self, FullType::Wpkh)
    }
}

impl<Pk> From<&Descriptor<Pk>> for FullType
where
    Pk: MiniscriptKey,
{
    fn from(descriptor: &Descriptor<Pk>) -> Self {
        match descriptor.desc_type() {
            DescriptorType::Bare => match descriptor {
                Descriptor::Bare(bare) => match bare.as_inner().node {
                    Terminal::PkK(_) => FullType::Pk,
                    _ => FullType::Bare,
                },
                _ => unreachable!(),
            },
            DescriptorType::Sh => FullType::Sh,
            DescriptorType::Pkh => FullType::Pkh,
            DescriptorType::Wpkh => FullType::Wpkh,
            DescriptorType::Wsh => FullType::Wsh,
            DescriptorType::ShWsh => FullType::ShWsh,
            DescriptorType::ShWpkh => FullType::ShWpkh,
            DescriptorType::ShSortedMulti => FullType::Sh,
            DescriptorType::WshSortedMulti => FullType::Wsh,
            DescriptorType::ShWshSortedMulti => FullType::ShWsh,
            DescriptorType::Tr => FullType::Tr,
        }
    }
}

impl FromStr for FullType {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().trim() {
            "bare" => FullType::Bare,
            "pk" => FullType::Pk,
            "pkh" => FullType::Pkh,
            "sh" => FullType::Sh,
            "shwpkh" => FullType::ShWpkh,
            "shwsh" => FullType::ShWsh,
            "wpkh" => FullType::Wpkh,
            "wsh" => FullType::Wsh,
            "tr" => FullType::Tr,
            unknown => return Err(ParseError::UnrecognizedDescriptorName(unknown.to_owned())),
        })
    }
}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[repr(u8)]
pub enum OuterType {
    #[display("bare")]
    Bare,

    #[display("pk")]
    Pk,

    #[display("pkh")]
    Pkh,

    #[display("sh")]
    Sh,

    #[display("wpkh")]
    Wpkh,

    #[display("wsh")]
    Wsh,

    #[display("tr")]
    Tr,
}

impl OuterType {
    pub fn outer_category(self) -> ContentType {
        match self {
            OuterType::Bare | OuterType::Pk => ContentType::Bare,
            OuterType::Pkh | OuterType::Sh => ContentType::Hashed,
            OuterType::Wpkh | OuterType::Wsh => ContentType::SegWit,
            OuterType::Tr => ContentType::Taproot,
        }
    }
}

impl From<FullType> for OuterType {
    fn from(full: FullType) -> Self {
        match full {
            FullType::Bare => OuterType::Bare,
            FullType::Pk => OuterType::Pk,
            FullType::Pkh => OuterType::Pkh,
            FullType::Sh => OuterType::Sh,
            FullType::Wpkh => OuterType::Wpkh,
            FullType::Wsh => OuterType::Wsh,
            FullType::ShWpkh => OuterType::Sh,
            FullType::ShWsh => OuterType::Sh,
            FullType::Tr => OuterType::Tr,
        }
    }
}

impl<Pk> From<&Descriptor<Pk>> for OuterType
where
    Pk: MiniscriptKey,
{
    fn from(descriptor: &Descriptor<Pk>) -> Self { FullType::from(descriptor).into() }
}

impl FromStr for OuterType {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().trim() {
            "bare" => OuterType::Bare,
            "pk" => OuterType::Pk,
            "pkh" => OuterType::Pkh,
            "sh" | "shWpkh" | "shWsh" => OuterType::Sh,
            "wpkh" => OuterType::Wpkh,
            "wsh" => OuterType::Wsh,
            "tr" => OuterType::Tr,
            unknown => return Err(ParseError::UnrecognizedDescriptorName(unknown.to_owned())),
        })
    }
}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[repr(u8)]
pub enum InnerType {
    #[display("bare")]
    Bare,

    #[display("pk")]
    Pk,

    #[display("pkh")]
    Pkh,

    #[display("sh")]
    Sh,

    #[display("wpkh")]
    Wpkh,

    #[display("wsh")]
    Wsh,

    #[display("tr")]
    Tr,
}

impl InnerType {
    pub fn inner_category(self) -> ContentType {
        match self {
            InnerType::Bare | InnerType::Pk => ContentType::Bare,
            InnerType::Pkh | InnerType::Sh => ContentType::Hashed,
            InnerType::Wpkh | InnerType::Wsh => ContentType::SegWit,
            InnerType::Tr => ContentType::Taproot,
        }
    }
}

impl From<FullType> for InnerType {
    fn from(full: FullType) -> Self {
        match full {
            FullType::Bare => InnerType::Bare,
            FullType::Pk => InnerType::Pk,
            FullType::Pkh => InnerType::Pkh,
            FullType::Sh => InnerType::Sh,
            FullType::Wpkh => InnerType::Wpkh,
            FullType::Wsh => InnerType::Wsh,
            FullType::ShWpkh => InnerType::Wpkh,
            FullType::ShWsh => InnerType::Wsh,
            FullType::Tr => InnerType::Tr,
        }
    }
}

impl<Pk> From<&Descriptor<Pk>> for InnerType
where
    Pk: MiniscriptKey,
{
    fn from(descriptor: &Descriptor<Pk>) -> Self { FullType::from(descriptor).into() }
}

impl FromStr for InnerType {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().trim() {
            "bare" => InnerType::Bare,
            "pk" => InnerType::Pk,
            "pkh" => InnerType::Pkh,
            "sh" => InnerType::Sh,
            "wpkh" | "shWpkh" => InnerType::Wpkh,
            "wsh" | "shWsh" => InnerType::Wsh,
            "tr" => InnerType::Tr,
            unknown => return Err(ParseError::UnrecognizedDescriptorName(unknown.to_owned())),
        })
    }
}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default)]
#[derive(StrictEncode, StrictDecode)]
#[repr(C)]
pub struct Variants {
    pub bare: bool,
    pub hashed: bool,
    pub nested: bool,
    pub segwit: bool,
    pub taproot: bool,
}

impl Display for Variants {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut comps = Vec::with_capacity(5);
        if self.bare {
            comps.push(if !f.alternate() { "bare" } else { "b" });
        }
        if self.hashed {
            comps.push(if !f.alternate() { "hashed" } else { "h" });
        }
        if self.nested {
            comps.push(if !f.alternate() { "nested" } else { "n" });
        }
        if self.segwit {
            comps.push(if !f.alternate() { "segwit" } else { "s" });
        }
        if self.taproot {
            comps.push(if !f.alternate() { "taproot" } else { "t" });
        }
        f.write_str(&comps.join("|"))
    }
}

impl FromStr for Variants {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut dv = Variants::default();
        for item in s.split('|') {
            match item.to_lowercase().as_str() {
                "b" | "bare" => dv.bare = true,
                "h" | "hashed" => dv.hashed = true,
                "n" | "nested" => dv.nested = true,
                "s" | "segwit" => dv.segwit = true,
                "t" | "taproot" => dv.taproot = true,
                unknown => return Err(ParseError::UnrecognizedDescriptorName(unknown.to_owned())),
            }
        }
        Ok(dv)
    }
}

impl Variants {
    pub fn count(&self) -> u32 {
        self.bare as u32
            + self.hashed as u32
            + self.nested as u32
            + self.segwit as u32
            + self.taproot as u32
    }

    pub fn has_match(&self, category: ConvertInfo) -> bool {
        match category {
            ConvertInfo::Bare => self.bare,
            ConvertInfo::Hashed => self.hashed,
            ConvertInfo::NestedV0 => self.nested,
            ConvertInfo::SegWitV0 => self.segwit,
            ConvertInfo::Taproot { .. } => self.taproot,
        }
    }
}

/// Descriptors exposing bare scripts (unlike [`miniscript::Descriptor`] which
/// uses miniscript representation of the scripts).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictEncode, StrictDecode)]
#[non_exhaustive]
pub enum BareDescriptor {
    Bare(PubkeyScript),

    Pk(bitcoin::PublicKey),

    Pkh(bitcoin::PublicKey),

    Sh(RedeemScript),

    ShWpkh(secp256k1::PublicKey),

    ShWsh(WitnessScript),

    Wpkh(secp256k1::PublicKey),

    Wsh(WitnessScript),

    Tr(UntweakedPublicKey, Option<TapBranchHash>),
}

impl Display for BareDescriptor {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            BareDescriptor::Bare(script) => {
                f.write_str("bare(")?;
                Display::fmt(script, f)?;
            }
            BareDescriptor::Pk(pk) => {
                f.write_str("pk(")?;
                Display::fmt(pk, f)?;
            }
            BareDescriptor::Pkh(pkh) => {
                f.write_str("pkh(")?;
                Display::fmt(pkh, f)?;
            }
            BareDescriptor::Sh(sh) => {
                f.write_str("sh(")?;
                Display::fmt(sh, f)?;
            }
            BareDescriptor::ShWpkh(pk) => {
                f.write_str("sh(wpkh(")?;
                Display::fmt(pk, f)?;
                f.write_str(")")?;
            }
            BareDescriptor::ShWsh(script) => {
                f.write_str("sh(wsh(")?;
                Display::fmt(script, f)?;
                f.write_str(")")?;
            }
            BareDescriptor::Wpkh(wpkh) => {
                f.write_str("wpkh(")?;
                Display::fmt(wpkh, f)?;
            }
            BareDescriptor::Wsh(wsh) => {
                f.write_str("wsh(")?;
                Display::fmt(wsh, f)?;
            }
            BareDescriptor::Tr(pk, None) => {
                f.write_str("tr(")?;
                Display::fmt(pk, f)?;
            }
            BareDescriptor::Tr(pk, Some(merkle_root)) => {
                f.write_str("tr(")?;
                Display::fmt(pk, f)?;
                f.write_str(",")?;
                Display::fmt(merkle_root, f)?;
            }
        }
        f.write_str(")")
    }
}

impl FromStr for BareDescriptor {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.trim_end_matches(')').split_once('(') {
            Some(("bare", inner)) => BareDescriptor::Bare(
                Script::from_str(inner)
                    .map_err(|_| Error::CantParseDescriptor)?
                    .into(),
            ),
            Some(("pk", inner)) => {
                BareDescriptor::Pk(inner.parse().map_err(|_| Error::CantParseDescriptor)?)
            }
            Some(("pkh", inner)) => {
                BareDescriptor::Pkh(inner.parse().map_err(|_| Error::CantParseDescriptor)?)
            }
            Some(("sh", inner)) => match inner.split_once('(') {
                None => BareDescriptor::Sh(
                    Script::from_str(inner)
                        .map_err(|_| Error::CantParseDescriptor)?
                        .into(),
                ),
                Some(("wpkh", inner)) => {
                    BareDescriptor::ShWpkh(inner.parse().map_err(|_| Error::CantParseDescriptor)?)
                }
                Some(("wsh", inner)) => BareDescriptor::ShWsh(
                    Script::from_str(inner)
                        .map_err(|_| Error::CantParseDescriptor)?
                        .into(),
                ),
                _ => return Err(Error::CantParseDescriptor),
            },
            Some(("wpkh", inner)) => {
                BareDescriptor::Wpkh(inner.parse().map_err(|_| Error::CantParseDescriptor)?)
            }
            Some(("wsh", inner)) => BareDescriptor::Wsh(
                Script::from_str(inner)
                    .map_err(|_| Error::CantParseDescriptor)?
                    .into(),
            ),
            Some(("tr", inner)) => {
                let (pk, merkle_root) = match inner.split_once(',') {
                    None => (inner, None),
                    Some((pk, merkle_root)) => (
                        pk,
                        Some(
                            merkle_root
                                .parse()
                                .map_err(|_| Error::CantParseDescriptor)?,
                        ),
                    ),
                };
                BareDescriptor::Tr(
                    pk.parse().map_err(|_| Error::CantParseDescriptor)?,
                    merkle_root,
                )
            }
            _ => return Err(Error::CantParseDescriptor),
        })
    }
}

impl BareDescriptor {
    pub fn pubkey_script<Ctx: Verification>(&self, secp: &Secp256k1<Ctx>) -> PubkeyScript {
        match self {
            BareDescriptor::Bare(pubkey_script) => pubkey_script.clone(),
            BareDescriptor::Pk(pk) => Script::new_p2pk(&pk).into(),
            BareDescriptor::Pkh(pk) => Script::new_p2pkh(&pk.pubkey_hash()).into(),
            BareDescriptor::Sh(script) => script.to_p2sh(),
            BareDescriptor::ShWpkh(pk) => pk
                .to_pubkey_script(ConvertInfo::NestedV0)
                .expect("uncompressed key"),
            BareDescriptor::ShWsh(script) => script
                .to_pubkey_script(ConvertInfo::NestedV0)
                .expect("uncompressed key"),
            BareDescriptor::Wpkh(pk) => pk
                .to_pubkey_script(ConvertInfo::SegWitV0)
                .expect("uncompressed key"),
            BareDescriptor::Wsh(script) => Script::new_v0_p2wsh(&script.script_hash()).into(),
            BareDescriptor::Tr(internal_key, merkle_root) => {
                Script::new_v1_p2tr(secp, *internal_key, *merkle_root).into()
            }
        }
    }
}

/// Descriptor parse error
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum ParseError {
    /// unrecognized descriptor name is used: {0}
    UnrecognizedDescriptorName(String),
}

// TODO #17: Derive `PartialOrd`, `Ord` & `Hash` once they will be implemented
//           for `miniscript::CompilerError`
#[derive(Clone, Copy, PartialEq, Eq, Display, Debug, From, Error)]
#[display(doc_comments)]
#[non_exhaustive]
pub enum Error {
    /// Can't deserealized public key from bitcoin script push op code
    InvalidKeyData,

    /// Wrong witness version, may be you need to upgrade used library version
    UnsupportedWitnessVersion,

    /// Policy compilation error
    #[from]
    #[display(inner)]
    PolicyCompilation(CompilerError),

    /// An uncompressed key can't be used in a SegWit script context
    UncompressedKeyInSegWitContext,

    /// Taproot does not have a lockscript representation
    Taproot,

    /// No locking script is possible for a single-sig
    SingleSig,

    /// Descriptor string parsing error
    CantParseDescriptor,
}

impl From<LockScriptError> for Error {
    fn from(err: LockScriptError) -> Self {
        match err {
            LockScriptError::UncompressedPubkeyInWitness(_) => {
                Error::UncompressedKeyInSegWitContext
            }
            LockScriptError::Taproot => Error::Taproot,
        }
    }
}
