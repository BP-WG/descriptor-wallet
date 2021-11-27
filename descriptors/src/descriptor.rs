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
pub enum SpkClass {
    #[display("bare")]
    Bare,

    #[display("hashed")]
    Hashed,

    #[display("segwit")]
    SegWit,

    #[display("taproot")]
    Taproot,
}

impl SpkClass {
    pub fn into_inner_type(self, script: bool) -> InnerDescrType {
        match (self, script) {
            (SpkClass::Bare, false) => InnerDescrType::Pk,
            (SpkClass::Hashed, false) => InnerDescrType::Pk,
            (SpkClass::SegWit, false) => InnerDescrType::Wpkh,

            (SpkClass::Bare, true) => InnerDescrType::Bare,
            (SpkClass::Hashed, true) => InnerDescrType::Sh,
            (SpkClass::SegWit, true) => InnerDescrType::Wsh,

            (SpkClass::Taproot, _) => InnerDescrType::Tr,
        }
    }

    pub fn into_simple_outer_type(self, script: bool) -> OuterDescrType {
        match (self, script) {
            (SpkClass::Bare, false) => OuterDescrType::Pk,
            (SpkClass::Hashed, false) => OuterDescrType::Pk,
            (SpkClass::SegWit, false) => OuterDescrType::Wpkh,

            (SpkClass::Bare, true) => OuterDescrType::Bare,
            (SpkClass::Hashed, true) => OuterDescrType::Sh,
            (SpkClass::SegWit, true) => OuterDescrType::Wsh,

            (SpkClass::Taproot, _) => OuterDescrType::Tr,
        }
    }

    pub fn into_nested_outer_type(self, script: bool) -> OuterDescrType {
        match (self, script) {
            (SpkClass::Bare, false) => OuterDescrType::Pk,
            (SpkClass::Hashed, false) => OuterDescrType::Pk,
            (SpkClass::SegWit, false) => OuterDescrType::Sh,

            (SpkClass::Bare, true) => OuterDescrType::Bare,
            (SpkClass::Hashed, true) => OuterDescrType::Sh,
            (SpkClass::SegWit, true) => OuterDescrType::Sh,

            (SpkClass::Taproot, _) => OuterDescrType::Tr,
        }
    }
}

impl From<CompositeDescrType> for SpkClass {
    fn from(full: CompositeDescrType) -> Self {
        match full {
            CompositeDescrType::Bare | CompositeDescrType::Pk => SpkClass::Bare,
            CompositeDescrType::Pkh | CompositeDescrType::Sh => SpkClass::Hashed,
            CompositeDescrType::Wpkh
            | CompositeDescrType::Wsh
            | CompositeDescrType::ShWpkh
            | CompositeDescrType::ShWsh => SpkClass::SegWit,
            CompositeDescrType::Tr => SpkClass::Taproot,
        }
    }
}

impl From<ConvertInfo> for SpkClass {
    fn from(category: ConvertInfo) -> Self {
        match category {
            ConvertInfo::Bare => SpkClass::Bare,
            ConvertInfo::Hashed => SpkClass::Hashed,
            ConvertInfo::NestedV0 | ConvertInfo::SegWitV0 => SpkClass::SegWit,
            ConvertInfo::Taproot { .. } => SpkClass::Taproot,
        }
    }
}

impl Default for SpkClass {
    fn default() -> Self { SpkClass::SegWit }
}

impl FromStr for SpkClass {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().trim() {
            "bare" | "pk" => SpkClass::Bare,
            "hashed" | "pkh" | "sh" => SpkClass::Hashed,
            "segwit" | "wsh" | "shwsh" | "wpkh" | "shwpkh" => SpkClass::SegWit,
            "taproot" | "tr" => SpkClass::Taproot,
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
pub enum CompositeDescrType {
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

impl CompositeDescrType {
    pub fn outer_category(self) -> SpkClass {
        match self {
            CompositeDescrType::Bare | CompositeDescrType::Pk => SpkClass::Bare,
            CompositeDescrType::Pkh | CompositeDescrType::Sh => SpkClass::Hashed,
            CompositeDescrType::Wpkh | CompositeDescrType::Wsh => SpkClass::SegWit,
            CompositeDescrType::ShWpkh | CompositeDescrType::ShWsh => SpkClass::Hashed,
            CompositeDescrType::Tr => SpkClass::Taproot,
        }
    }

    pub fn inner_category(self) -> SpkClass {
        match self {
            CompositeDescrType::Bare | CompositeDescrType::Pk => SpkClass::Bare,
            CompositeDescrType::Pkh | CompositeDescrType::Sh => SpkClass::Hashed,
            CompositeDescrType::Wpkh | CompositeDescrType::Wsh => SpkClass::SegWit,
            CompositeDescrType::ShWpkh | CompositeDescrType::ShWsh => SpkClass::SegWit,
            CompositeDescrType::Tr => SpkClass::Taproot,
        }
    }

    #[inline]
    pub fn is_segwit(self) -> bool { self.inner_category() == SpkClass::SegWit }

    #[inline]
    pub fn is_taproot(self) -> bool { self == CompositeDescrType::Tr }

    #[inline]
    pub fn has_redeem_script(self) -> bool {
        matches!(
            self,
            CompositeDescrType::ShWsh | CompositeDescrType::ShWpkh | CompositeDescrType::Sh
        )
    }

    #[inline]
    pub fn has_witness_script(self) -> bool {
        self.is_segwit() && !self.is_taproot() && !matches!(self, CompositeDescrType::Wpkh)
    }
}

impl<Pk> From<&Descriptor<Pk>> for CompositeDescrType
where
    Pk: MiniscriptKey,
{
    fn from(descriptor: &Descriptor<Pk>) -> Self {
        match descriptor.desc_type() {
            DescriptorType::Bare => match descriptor {
                Descriptor::Bare(bare) => match bare.as_inner().node {
                    Terminal::PkK(_) => CompositeDescrType::Pk,
                    _ => CompositeDescrType::Bare,
                },
                _ => unreachable!(),
            },
            DescriptorType::Sh => CompositeDescrType::Sh,
            DescriptorType::Pkh => CompositeDescrType::Pkh,
            DescriptorType::Wpkh => CompositeDescrType::Wpkh,
            DescriptorType::Wsh => CompositeDescrType::Wsh,
            DescriptorType::ShWsh => CompositeDescrType::ShWsh,
            DescriptorType::ShWpkh => CompositeDescrType::ShWpkh,
            DescriptorType::ShSortedMulti => CompositeDescrType::Sh,
            DescriptorType::WshSortedMulti => CompositeDescrType::Wsh,
            DescriptorType::ShWshSortedMulti => CompositeDescrType::ShWsh,
            DescriptorType::Tr => CompositeDescrType::Tr,
        }
    }
}

impl FromStr for CompositeDescrType {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().trim() {
            "bare" => CompositeDescrType::Bare,
            "pk" => CompositeDescrType::Pk,
            "pkh" => CompositeDescrType::Pkh,
            "sh" => CompositeDescrType::Sh,
            "shwpkh" => CompositeDescrType::ShWpkh,
            "shwsh" => CompositeDescrType::ShWsh,
            "wpkh" => CompositeDescrType::Wpkh,
            "wsh" => CompositeDescrType::Wsh,
            "tr" => CompositeDescrType::Tr,
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
pub enum OuterDescrType {
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

impl OuterDescrType {
    pub fn outer_category(self) -> SpkClass {
        match self {
            OuterDescrType::Bare | OuterDescrType::Pk => SpkClass::Bare,
            OuterDescrType::Pkh | OuterDescrType::Sh => SpkClass::Hashed,
            OuterDescrType::Wpkh | OuterDescrType::Wsh => SpkClass::SegWit,
            OuterDescrType::Tr => SpkClass::Taproot,
        }
    }
}

impl From<CompositeDescrType> for OuterDescrType {
    fn from(full: CompositeDescrType) -> Self {
        match full {
            CompositeDescrType::Bare => OuterDescrType::Bare,
            CompositeDescrType::Pk => OuterDescrType::Pk,
            CompositeDescrType::Pkh => OuterDescrType::Pkh,
            CompositeDescrType::Sh => OuterDescrType::Sh,
            CompositeDescrType::Wpkh => OuterDescrType::Wpkh,
            CompositeDescrType::Wsh => OuterDescrType::Wsh,
            CompositeDescrType::ShWpkh => OuterDescrType::Sh,
            CompositeDescrType::ShWsh => OuterDescrType::Sh,
            CompositeDescrType::Tr => OuterDescrType::Tr,
        }
    }
}

impl<Pk> From<&Descriptor<Pk>> for OuterDescrType
where
    Pk: MiniscriptKey,
{
    fn from(descriptor: &Descriptor<Pk>) -> Self { CompositeDescrType::from(descriptor).into() }
}

impl FromStr for OuterDescrType {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().trim() {
            "bare" => OuterDescrType::Bare,
            "pk" => OuterDescrType::Pk,
            "pkh" => OuterDescrType::Pkh,
            "sh" | "shWpkh" | "shWsh" => OuterDescrType::Sh,
            "wpkh" => OuterDescrType::Wpkh,
            "wsh" => OuterDescrType::Wsh,
            "tr" => OuterDescrType::Tr,
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
pub enum InnerDescrType {
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

impl InnerDescrType {
    pub fn inner_category(self) -> SpkClass {
        match self {
            InnerDescrType::Bare | InnerDescrType::Pk => SpkClass::Bare,
            InnerDescrType::Pkh | InnerDescrType::Sh => SpkClass::Hashed,
            InnerDescrType::Wpkh | InnerDescrType::Wsh => SpkClass::SegWit,
            InnerDescrType::Tr => SpkClass::Taproot,
        }
    }
}

impl From<CompositeDescrType> for InnerDescrType {
    fn from(full: CompositeDescrType) -> Self {
        match full {
            CompositeDescrType::Bare => InnerDescrType::Bare,
            CompositeDescrType::Pk => InnerDescrType::Pk,
            CompositeDescrType::Pkh => InnerDescrType::Pkh,
            CompositeDescrType::Sh => InnerDescrType::Sh,
            CompositeDescrType::Wpkh => InnerDescrType::Wpkh,
            CompositeDescrType::Wsh => InnerDescrType::Wsh,
            CompositeDescrType::ShWpkh => InnerDescrType::Wpkh,
            CompositeDescrType::ShWsh => InnerDescrType::Wsh,
            CompositeDescrType::Tr => InnerDescrType::Tr,
        }
    }
}

impl<Pk> From<&Descriptor<Pk>> for InnerDescrType
where
    Pk: MiniscriptKey,
{
    fn from(descriptor: &Descriptor<Pk>) -> Self { CompositeDescrType::from(descriptor).into() }
}

impl FromStr for InnerDescrType {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().trim() {
            "bare" => InnerDescrType::Bare,
            "pk" => InnerDescrType::Pk,
            "pkh" => InnerDescrType::Pkh,
            "sh" => InnerDescrType::Sh,
            "wpkh" | "shWpkh" => InnerDescrType::Wpkh,
            "wsh" | "shWsh" => InnerDescrType::Wsh,
            "tr" => InnerDescrType::Tr,
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
pub struct DescrVariants {
    pub bare: bool,
    pub hashed: bool,
    pub nested: bool,
    pub segwit: bool,
    pub taproot: bool,
}

impl Display for DescrVariants {
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

impl FromStr for DescrVariants {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut dv = DescrVariants::default();
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

impl DescrVariants {
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
