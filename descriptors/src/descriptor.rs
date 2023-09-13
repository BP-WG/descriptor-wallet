// Wallet-level libraries for bitcoin protocol by LNP/BP Association
//
// Written in 2020-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// This software is distributed without any warranty.
//
// You should have received a copy of the Apache-2.0 License
// along with this software.
// If not, see <https://opensource.org/licenses/Apache-2.0>.

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use amplify::Wrapper;
use bitcoin::address::WitnessVersion;
use bitcoin::hashes::Hash;
use bitcoin::key::{TweakedPublicKey, UntweakedPublicKey, XOnlyPublicKey};
use bitcoin::secp256k1::{self, Secp256k1, Verification};
use bitcoin::taproot::TapNodeHash;
use bitcoin::{PubkeyHash, Script, ScriptHash, WPubkeyHash, WScriptHash};
use bitcoin_hd::Bip43;
#[cfg(not(feature = "miniscript"))]
use bitcoin_hd::DescriptorType;
#[cfg(feature = "miniscript")]
use miniscript::descriptor::DescriptorType;
#[cfg(feature = "miniscript")]
use miniscript::policy::compiler::CompilerError;
#[cfg(feature = "miniscript")]
use miniscript::{Descriptor, MiniscriptKey, Terminal};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub enum DescriptorClass {
    PreSegwit,
    SegwitV0,
    NestedV0,
    TaprootC0,
}

impl From<&DescriptorType> for DescriptorClass {
    fn from(ty: &DescriptorType) -> Self {
        match ty {
            DescriptorType::Bare
            | DescriptorType::Sh
            | DescriptorType::ShSortedMulti
            | DescriptorType::Pkh => DescriptorClass::PreSegwit,
            DescriptorType::Wpkh | DescriptorType::WshSortedMulti | DescriptorType::Wsh => {
                DescriptorClass::SegwitV0
            }
            DescriptorType::ShWsh | DescriptorType::ShWshSortedMulti | DescriptorType::ShWpkh => {
                DescriptorClass::NestedV0
            }
            DescriptorType::Tr => DescriptorClass::TaprootC0,
        }
    }
}

impl From<DescriptorType> for DescriptorClass {
    fn from(ty: DescriptorType) -> Self { DescriptorClass::from(&ty) }
}

impl DescriptorClass {
    pub fn bip43(self, sigs_no: usize) -> Bip43 {
        match (self, sigs_no > 1) {
            (DescriptorClass::PreSegwit, false) => Bip43::singlesig_pkh(),
            (DescriptorClass::SegwitV0, false) => Bip43::singlesig_segwit0(),
            (DescriptorClass::NestedV0, false) => Bip43::singlesig_nested0(),
            (DescriptorClass::TaprootC0, false) => Bip43::singlesig_taproot(),
            (DescriptorClass::PreSegwit, true) => Bip43::multisig_ordered_sh(),
            (DescriptorClass::SegwitV0, true) => Bip43::multisig_segwit0(),
            (DescriptorClass::NestedV0, true) => Bip43::multisig_nested0(),
            (DescriptorClass::TaprootC0, true) => Bip43::multisig_descriptor(),
        }
    }

    pub fn is_segwit_v0(self) -> bool {
        match self {
            DescriptorClass::SegwitV0 | DescriptorClass::NestedV0 => true,
            DescriptorClass::PreSegwit | DescriptorClass::TaprootC0 => false,
        }
    }
}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug, Display
)]
#[repr(u8)]
pub enum SpkClass {
    #[display("bare")]
    Bare,

    #[display("hashed")]
    Hashed,

    #[default]
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

#[cfg(feature = "miniscript")]
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

#[cfg(feature = "miniscript")]
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
            "sh" | "shwpkh" | "shwsh" => OuterDescrType::Sh,
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

#[cfg(feature = "miniscript")]
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
            "wpkh" | "shwpkh" => InnerDescrType::Wpkh,
            "wsh" | "shwsh" => InnerDescrType::Wsh,
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
}

#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Debug, Display)]
#[non_exhaustive]
pub enum ScriptPubkeyDescr {
    #[display("bare({0})", alt = "bare({0:#})")]
    Bare(PubkeyScript),

    #[display("pk({0})")]
    Pk(bitcoin::PublicKey),

    #[display("pkh({0})")]
    Pkh(PubkeyHash),

    #[display("sh({0})")]
    Sh(ScriptHash),

    #[display("wpkh({0})")]
    Wpkh(WPubkeyHash),

    #[display("wsh({0})")]
    Wsh(WScriptHash),

    #[display("tr({0})")]
    Tr(TweakedPublicKey),
}

impl FromStr for ScriptPubkeyDescr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = &s[..s.len() - 1];
        if s.starts_with("bare(") {
            let inner = s.trim_start_matches("bare(");
            Ok(ScriptPubkeyDescr::Bare(
                Script::from_str(inner)
                    .map_err(|_| Error::CantParseDescriptor)?
                    .into(),
            ))
        } else if s.starts_with("pk(") {
            let inner = s.trim_start_matches("pk(");
            Ok(ScriptPubkeyDescr::Pk(
                inner.parse().map_err(|_| Error::CantParseDescriptor)?,
            ))
        } else if s.starts_with("pkh(") {
            let inner = s.trim_start_matches("pkh(");
            Ok(ScriptPubkeyDescr::Pkh(
                inner.parse().map_err(|_| Error::CantParseDescriptor)?,
            ))
        } else if s.starts_with("sh(") {
            let inner = s.trim_start_matches("sh(");
            Ok(ScriptPubkeyDescr::Sh(
                inner.parse().map_err(|_| Error::CantParseDescriptor)?,
            ))
        } else if s.starts_with("wpkh(") {
            let inner = s.trim_start_matches("wpkh(");
            Ok(ScriptPubkeyDescr::Wpkh(
                inner.parse().map_err(|_| Error::CantParseDescriptor)?,
            ))
        } else if s.starts_with("wsh(") {
            let inner = s.trim_start_matches("wsh(");
            Ok(ScriptPubkeyDescr::Wsh(
                inner.parse().map_err(|_| Error::CantParseDescriptor)?,
            ))
        } else if s.starts_with("tr(") {
            let inner = s.trim_start_matches("tr(");
            let pk = XOnlyPublicKey::from_str(inner).map_err(|_| Error::CantParseDescriptor)?;
            Ok(ScriptPubkeyDescr::Tr(
                TweakedPublicKey::dangerous_assume_tweaked(pk),
            ))
        } else {
            Err(Error::CantParseDescriptor)
        }
    }
}

/// Errors indicating variants of misformatted or unsupported (future)
/// `pubkeyScript`
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error, From
)]
#[display(doc_comments)]
pub enum UnsupportedScriptPubkey {
    /// public key in `scriptPubkey` does not belong to Secp256k1 curve
    #[from(bitcoin::key::Error)]
    #[from(secp256k1::Error)]
    WrongPubkeyValue,

    /// input spends non-taproot witness version 1
    NonTaprootV1,

    /// input spends future witness version {0}
    UnsupportedWitnessVersion(WitnessVersion),
}

impl TryFrom<PubkeyScript> for ScriptPubkeyDescr {
    type Error = UnsupportedScriptPubkey;

    fn try_from(spk: PubkeyScript) -> Result<Self, Self::Error> {
        let script = spk.as_inner();
        let bytes = script.as_bytes();
        match (&spk, spk.witness_version()) {
            (spk, _) if spk.is_p2pk() && script.len() == 67 => Ok(ScriptPubkeyDescr::Pk(
                bitcoin::PublicKey::from_slice(&bytes[1..66])?,
            )),
            (spk, _) if spk.is_p2pk() && script.len() == 35 => Ok(ScriptPubkeyDescr::Pk(
                bitcoin::PublicKey::from_slice(&bytes[1..34])?,
            )),
            (spk, _) if spk.is_p2pkh() => {
                let mut hash_inner = [0u8; 20];
                hash_inner.copy_from_slice(&bytes[3..23]);
                Ok(ScriptPubkeyDescr::Pkh(PubkeyHash::from_inner(hash_inner)))
            }
            (spk, _) if spk.is_v0_p2wpkh() => {
                let mut hash_inner = [0u8; 20];
                hash_inner.copy_from_slice(&bytes[2..]);
                Ok(ScriptPubkeyDescr::Wpkh(WPubkeyHash::from_inner(hash_inner)))
            }
            (spk, _) if spk.is_v0_p2wsh() => {
                let mut hash_inner = [0u8; 32];
                hash_inner.copy_from_slice(&bytes[2..]);
                Ok(ScriptPubkeyDescr::Wsh(WScriptHash::from_inner(hash_inner)))
            }
            (spk, _) if spk.is_v1_p2tr() => Ok(ScriptPubkeyDescr::Tr(
                TweakedPublicKey::dangerous_assume_tweaked(XOnlyPublicKey::from_slice(
                    &bytes[2..],
                )?),
            )),
            (spk, _) if spk.is_p2sh() => {
                let mut hash_inner = [0u8; 20];
                hash_inner.copy_from_slice(&bytes[2..22]);
                Ok(ScriptPubkeyDescr::Sh(ScriptHash::from_inner(hash_inner)))
            }
            (_, Some(WitnessVersion::V1)) => Err(UnsupportedScriptPubkey::NonTaprootV1),
            (_, Some(version)) => Err(UnsupportedScriptPubkey::UnsupportedWitnessVersion(version)),
            (_, None) => Ok(ScriptPubkeyDescr::Bare(spk)),
        }
    }
}

/// Descriptors exposing bare scripts (unlike [`miniscript::Descriptor`] which
/// uses miniscript representation of the scripts).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
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

    Tr(UntweakedPublicKey, Option<TapNodeHash>),
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
            BareDescriptor::Pk(pk) => Script::new_p2pk(pk).into(),
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

#[cfg(not(feature = "miniscript"))]
#[derive(
    Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error
)]
#[display(Debug)]
pub enum CompilerError {}

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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn outer_descr_type_from_str() {
        assert_eq!(OuterDescrType::from_str("bare"), Ok(OuterDescrType::Bare));
        assert_eq!(OuterDescrType::from_str("pk"), Ok(OuterDescrType::Pk));
        assert_eq!(OuterDescrType::from_str("pkh"), Ok(OuterDescrType::Pkh));
        assert_eq!(OuterDescrType::from_str("sh"), Ok(OuterDescrType::Sh));
        assert_eq!(OuterDescrType::from_str("shwpkh"), Ok(OuterDescrType::Sh));
        assert_eq!(OuterDescrType::from_str("shwsh"), Ok(OuterDescrType::Sh));
        assert_eq!(OuterDescrType::from_str("wpkh"), Ok(OuterDescrType::Wpkh));
        assert_eq!(OuterDescrType::from_str("wsh"), Ok(OuterDescrType::Wsh));
        assert_eq!(OuterDescrType::from_str("tr"), Ok(OuterDescrType::Tr));

        assert_eq!(OuterDescrType::from_str("BARE"), Ok(OuterDescrType::Bare));
        assert_eq!(OuterDescrType::from_str(" BARE "), Ok(OuterDescrType::Bare));

        assert_eq!(
            OuterDescrType::from_str("???"),
            Err(ParseError::UnrecognizedDescriptorName("???".into()))
        );
    }

    #[test]
    fn inner_descr_type_from_str() {
        assert_eq!(InnerDescrType::from_str("bare"), Ok(InnerDescrType::Bare));
        assert_eq!(InnerDescrType::from_str("pk"), Ok(InnerDescrType::Pk));
        assert_eq!(InnerDescrType::from_str("pkh"), Ok(InnerDescrType::Pkh));
        assert_eq!(InnerDescrType::from_str("sh"), Ok(InnerDescrType::Sh));
        assert_eq!(InnerDescrType::from_str("wpkh"), Ok(InnerDescrType::Wpkh));
        assert_eq!(InnerDescrType::from_str("shwpkh"), Ok(InnerDescrType::Wpkh));
        assert_eq!(InnerDescrType::from_str("wsh"), Ok(InnerDescrType::Wsh));
        assert_eq!(InnerDescrType::from_str("shwsh"), Ok(InnerDescrType::Wsh));
        assert_eq!(InnerDescrType::from_str("tr"), Ok(InnerDescrType::Tr));

        assert_eq!(InnerDescrType::from_str("BARE"), Ok(InnerDescrType::Bare));
        assert_eq!(InnerDescrType::from_str(" BARE "), Ok(InnerDescrType::Bare));

        assert_eq!(
            InnerDescrType::from_str("???"),
            Err(ParseError::UnrecognizedDescriptorName("???".into()))
        );
    }
}
