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

use std::convert::TryFrom;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use bitcoin::hashes::Hash;
use bitcoin::secp256k1;
use bitcoin::secp256k1::schnorrsig as bip340;
use bitcoin::{PubkeyHash, Script, ScriptHash, WPubkeyHash, WScriptHash};
use miniscript::policy::compiler::CompilerError;

use bitcoin_scripts::{
    Category, PubkeyScript, RedeemScript, TapScript, ToPubkeyScript,
    WitnessScript,
};
use miniscript::descriptor::DescriptorType;
use miniscript::{Descriptor, MiniscriptKey, Terminal};

#[derive(
    Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error,
)]
#[display(doc_comments)]
pub enum ParseError {
    /// unrecognized descriptor name is used: {0}
    UnrecognizedDescriptorName(String),
}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Clone,
    Copy,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
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
        Category::from(full).into()
    }
}

impl From<Category> for ContentType {
    fn from(category: Category) -> Self {
        match category {
            Category::Bare => ContentType::Bare,
            Category::Hashed => ContentType::Hashed,
            Category::Nested | Category::SegWit => ContentType::SegWit,
            Category::Taproot => ContentType::Taproot,
        }
    }
}

impl Default for ContentType {
    fn default() -> Self {
        ContentType::SegWit
    }
}

impl FromStr for ContentType {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().trim() {
            "bare" | "pk" => ContentType::Bare,
            "hashed" | "pkh" | "sh" => ContentType::Hashed,
            "segwit" | "wsh" | "shwsh" | "wpkh" | "shwpkh" => {
                ContentType::SegWit
            }
            "taproot" | "tr" => ContentType::Taproot,
            unknown => {
                Err(ParseError::UnrecognizedDescriptorName(unknown.to_owned()))?
            }
        })
    }
}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Clone,
    Copy,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
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
}

impl<Pk> From<Descriptor<Pk>> for FullType
where
    Pk: MiniscriptKey,
{
    fn from(descriptor: Descriptor<Pk>) -> Self {
        match descriptor.desc_type() {
            DescriptorType::Bare => match descriptor {
                Descriptor::Bare(bare) => match bare.into_inner().node {
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
            "shWpkh" => FullType::ShWpkh,
            "shWsh" => FullType::ShWsh,
            "wpkh" => FullType::Wpkh,
            "wsh" => FullType::Wsh,
            "tr" => FullType::Tr,
            unknown => {
                Err(ParseError::UnrecognizedDescriptorName(unknown.to_owned()))?
            }
        })
    }
}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Clone,
    Copy,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
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

impl<Pk> From<Descriptor<Pk>> for OuterType
where
    Pk: MiniscriptKey,
{
    fn from(descriptor: Descriptor<Pk>) -> Self {
        FullType::from(descriptor).into()
    }
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
            unknown => {
                Err(ParseError::UnrecognizedDescriptorName(unknown.to_owned()))?
            }
        })
    }
}

impl From<FullType> for Category {
    fn from(full: FullType) -> Self {
        match full {
            FullType::Bare | FullType::Pk => Category::Bare,
            FullType::Pkh | FullType::Sh => Category::Hashed,
            FullType::Wpkh | FullType::Wsh => Category::SegWit,
            FullType::ShWpkh | FullType::ShWsh => Category::Nested,
            FullType::Tr => Category::Taproot,
        }
    }
}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Clone,
    Copy,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
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

impl<Pk> From<Descriptor<Pk>> for InnerType
where
    Pk: MiniscriptKey,
{
    fn from(descriptor: Descriptor<Pk>) -> Self {
        FullType::from(descriptor).into()
    }
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
            unknown => {
                Err(ParseError::UnrecognizedDescriptorName(unknown.to_owned()))?
            }
        })
    }
}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Clone,
    Copy,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    Default,
    StrictEncode,
    StrictDecode,
)]
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
                unknown => Err(ParseError::UnrecognizedDescriptorName(
                    unknown.to_owned(),
                ))?,
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

    pub fn has_match(&self, category: Category) -> bool {
        match category {
            Category::Bare => self.bare,
            Category::Hashed => self.hashed,
            Category::Nested => self.nested,
            Category::SegWit => self.segwit,
            Category::Taproot => self.taproot,
        }
    }
}

#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    From,
    StrictEncode,
    StrictDecode,
)]
#[non_exhaustive]
pub enum Compact {
    #[display("bare({0})", alt = "bare({_0:#})")]
    Bare(PubkeyScript),

    #[display("pk({0})")]
    #[from]
    Pk(bitcoin::PublicKey),

    #[display("pkh({0})")]
    #[from]
    Pkh(PubkeyHash),

    #[display("sh({0})")]
    #[from]
    Sh(ScriptHash),

    #[display("wpkh({0})")]
    #[from]
    Wpkh(WPubkeyHash),

    #[display("wsh({0})")]
    #[from]
    Wsh(WScriptHash),

    #[display("tr({0})")]
    #[from]
    Taproot(bip340::PublicKey),
}

impl FromStr for Compact {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = &s[..s.len() - 1];
        if s.starts_with("bare(") {
            let inner = s.trim_start_matches("bare(");
            Ok(Compact::Bare(
                Script::from_str(inner)
                    .map_err(|_| Error::CantParseDescriptor)?
                    .into(),
            ))
        } else if s.starts_with("pk(") {
            let inner = s.trim_start_matches("pk(");
            Ok(Compact::Pk(
                inner.parse().map_err(|_| Error::CantParseDescriptor)?,
            ))
        } else if s.starts_with("pkh(") {
            let inner = s.trim_start_matches("pkh(");
            Ok(Compact::Pkh(
                inner.parse().map_err(|_| Error::CantParseDescriptor)?,
            ))
        } else if s.starts_with("sh(") {
            let inner = s.trim_start_matches("sh(");
            Ok(Compact::Sh(
                inner.parse().map_err(|_| Error::CantParseDescriptor)?,
            ))
        } else if s.starts_with("wpkh(") {
            let inner = s.trim_start_matches("wpkh(");
            Ok(Compact::Wpkh(
                inner.parse().map_err(|_| Error::CantParseDescriptor)?,
            ))
        } else if s.starts_with("wsh(") {
            let inner = s.trim_start_matches("wsh(");
            Ok(Compact::Wsh(
                inner.parse().map_err(|_| Error::CantParseDescriptor)?,
            ))
        } else if s.starts_with("tr(") {
            let inner = s.trim_start_matches("tr(");
            Ok(Compact::Taproot(
                inner.parse().map_err(|_| Error::CantParseDescriptor)?,
            ))
        } else {
            Err(Error::CantParseDescriptor)
        }
    }
}

#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
#[non_exhaustive]
pub enum Expanded {
    #[display("bare({0})", alt = "bare({_0:#})")]
    Bare(PubkeyScript),

    #[display("pk({0})")]
    Pk(bitcoin::PublicKey),

    #[display("pkh({0})")]
    Pkh(bitcoin::PublicKey),

    #[display("sh({0})")]
    Sh(RedeemScript),

    #[display("sh(wpkh({0}))", alt = "sh(wpkh({_0:#}))")]
    ShWpkh(bitcoin::PublicKey),

    #[display("sh(wsh({0}))")]
    ShWsh(WitnessScript),

    #[display("wpkh({0})")]
    Wpkh(bitcoin::PublicKey),

    #[display("wsh({0})")]
    Wsh(WitnessScript),

    #[display("tr({0})")]
    Taproot(secp256k1::PublicKey, TapScript),
}

impl From<Expanded> for PubkeyScript {
    fn from(expanded: Expanded) -> PubkeyScript {
        match expanded {
            Expanded::Bare(pubkey_script) => pubkey_script,
            Expanded::Pk(pk) => pk.to_pubkey_script(Category::Bare),
            Expanded::Pkh(pk) => pk.to_pubkey_script(Category::Hashed),
            Expanded::Sh(script) => script.to_pubkey_script(Category::Hashed),
            Expanded::ShWpkh(pk) => pk.to_pubkey_script(Category::Nested),
            Expanded::ShWsh(script) => {
                script.to_pubkey_script(Category::Nested)
            }
            Expanded::Wpkh(pk) => pk.to_pubkey_script(Category::SegWit),
            Expanded::Wsh(script) => script.to_pubkey_script(Category::SegWit),
            Expanded::Taproot(..) => unimplemented!(),
        }
    }
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

    /// Descriptor string parsing error
    CantParseDescriptor,
}

impl TryFrom<PubkeyScript> for Compact {
    type Error = Error;
    fn try_from(script_pubkey: PubkeyScript) -> Result<Self, Self::Error> {
        use bitcoin::blockdata::opcodes::all::*;
        use Compact::*;

        let script = &*script_pubkey;
        let p = script.as_bytes();
        Ok(match script {
            s if s.is_p2pk() => {
                let key = match p[0].into() {
                    OP_PUSHBYTES_65 => {
                        bitcoin::PublicKey::from_slice(&p[1..66])
                    }
                    OP_PUSHBYTES_33 => {
                        bitcoin::PublicKey::from_slice(&p[1..34])
                    }
                    _ => panic!("Reading hash from fixed slice failed"),
                }
                .map_err(|_| Error::InvalidKeyData)?;
                Pk(key)
            }
            s if s.is_p2pkh() => Pkh(PubkeyHash::from_slice(&p[3..23])
                .expect("Reading hash from fixed slice failed")),
            s if s.is_p2sh() => Sh(ScriptHash::from_slice(&p[2..22])
                .expect("Reading hash from fixed slice failed")),
            s if s.is_v0_p2wpkh() => Wpkh(
                WPubkeyHash::from_slice(&p[2..22])
                    .expect("Reading hash from fixed slice failed"),
            ),
            s if s.is_v0_p2wsh() => Wsh(WScriptHash::from_slice(&p[2..34])
                .expect("Reading hash from fixed slice failed")),
            s if s.is_witness_program() => {
                Err(Error::UnsupportedWitnessVersion)?
            }
            _ => Bare(script_pubkey),
        })
    }
}

impl From<Compact> for PubkeyScript {
    fn from(spkt: Compact) -> PubkeyScript {
        use Compact::*;

        PubkeyScript::from(match spkt {
            Bare(script) => (*script).clone(),
            Pk(pubkey) => Script::new_p2pk(&pubkey),
            Pkh(pubkey_hash) => Script::new_p2pkh(&pubkey_hash),
            Sh(script_hash) => Script::new_p2sh(&script_hash),
            Wpkh(wpubkey_hash) => Script::new_v0_wpkh(&wpubkey_hash),
            Wsh(wscript_hash) => Script::new_v0_wsh(&wscript_hash),
            Taproot(_) => unimplemented!(),
        })
    }
}
