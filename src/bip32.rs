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

use regex::Regex;
use std::cmp::Ordering;
use std::convert::TryFrom;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::iter::FromIterator;
use std::ops::RangeInclusive;
use std::str::FromStr;

use amplify::Wrapper;
use bitcoin::util::bip32::{
    self, ChildNumber, DerivationPath, Error, ExtendedPubKey, Fingerprint,
};
use bitcoin::XpubIdentifier;
use miniscript::MiniscriptKey;
use slip132::FromSlip132;
use strict_encoding::{self, StrictDecode, StrictEncode};

/// Constant determining BIP32 boundary for u32 values after which index
/// is treated as hardened
pub const HARDENED_INDEX_BOUNDARY: u32 = 1 << 31;

#[derive(
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    Display,
    From,
    StrictEncode,
    StrictDecode,
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "lowercase")
)]
#[display("=[{0}]", alt = "=[{0:#}]")]
pub enum XpubRef {
    #[display("")]
    None,

    #[from]
    Fingerprint(Fingerprint),

    #[from]
    XpubIdentifier(XpubIdentifier),

    #[from]
    Xpub(ExtendedPubKey),
}

impl FromStr for XpubRef {
    type Err = bip32::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim_start_matches('=');
        if s.trim() == "" {
            return Ok(XpubRef::None);
        }
        Ok(Fingerprint::from_str(s)
            .map(XpubRef::from)
            .or_else(|_| XpubIdentifier::from_str(s).map(XpubRef::from))
            .map_err(|_| bip32::Error::InvalidDerivationPathFormat)
            .or_else(|_| ExtendedPubKey::from_str(s).map(XpubRef::from))?)
    }
}

// -----------------------------------------------------------------------------

pub trait ChildIndex
where
    Self:
        Sized + TryFrom<ChildNumber> + From<u8> + From<u16> + FromStr + Display,
    ChildNumber: TryFrom<Self>,
{
    #[inline]
    fn zero() -> Self {
        Self::from_index(0u8).expect("Broken ChildIndex implementation")
    }

    #[inline]
    fn one() -> Self {
        Self::from_index(1u8).expect("Broken ChildIndex implementation")
    }

    fn from_index(index: impl Into<u32>) -> Result<Self, bip32::Error>;

    fn index(self) -> Option<u32>;

    fn index_mut(&mut self) -> Option<&mut u32>;

    fn try_increment(&mut self) -> Result<u32, bip32::Error> {
        let index = self
            .index_mut()
            .ok_or(bip32::Error::InvalidChildNumberFormat)?;
        if *index >= HARDENED_INDEX_BOUNDARY {
            return Err(bip32::Error::InvalidChildNumber(*index));
        }
        *index += 1;
        Ok(*index)
    }

    fn try_decrement(&mut self) -> Result<u32, bip32::Error> {
        let index = self
            .index_mut()
            .ok_or(bip32::Error::InvalidChildNumberFormat)?;
        if *index == 0 {
            return Err(bip32::Error::InvalidChildNumber(*index));
        }
        *index -= 1;
        Ok(*index)
    }

    fn incremented(mut self) -> Result<Self, bip32::Error> {
        let index = self
            .index_mut()
            .ok_or(bip32::Error::InvalidChildNumberFormat)?;
        if *index >= HARDENED_INDEX_BOUNDARY {
            return Err(bip32::Error::InvalidChildNumber(*index));
        }
        *index += 1;
        Ok(self)
    }

    fn decremented(mut self) -> Result<Self, bip32::Error> {
        let index = self
            .index_mut()
            .ok_or(bip32::Error::InvalidChildNumberFormat)?;
        if *index == 0 {
            return Err(bip32::Error::InvalidChildNumber(*index));
        }
        *index -= 1;
        Ok(self)
    }

    fn is_hardened(&self) -> bool;
}

/// Index for unhardened children derivation; ensures that the wrapped value
/// < 2^31
#[derive(
    Clone,
    Copy,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Debug,
    Hash,
    Default,
    Display,
    From,
    StrictEncode,
    StrictDecode,
)]
#[display(inner)]
pub struct UnhardenedIndex(
    #[from(u8)]
    #[from(u16)]
    pub(self) u32,
);

impl ChildIndex for UnhardenedIndex {
    #[inline]
    fn from_index(index: impl Into<u32>) -> Result<Self, bip32::Error> {
        let index = index.into();
        if index >= HARDENED_INDEX_BOUNDARY {
            Err(bip32::Error::InvalidChildNumber(index))
        } else {
            Ok(Self(index))
        }
    }

    #[inline]
    fn index(self) -> Option<u32> {
        Some(self.0)
    }

    #[inline]
    fn index_mut(&mut self) -> Option<&mut u32> {
        Some(&mut self.0)
    }

    #[inline]
    fn is_hardened(&self) -> bool {
        false
    }
}

impl FromStr for UnhardenedIndex {
    type Err = bip32::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        UnhardenedIndex::from_index(
            u32::from_str(s)
                .map_err(|_| bip32::Error::InvalidChildNumberFormat)?,
        )
    }
}

impl From<UnhardenedIndex> for u32 {
    fn from(index: UnhardenedIndex) -> Self {
        index.0
    }
}

impl TryFrom<ChildNumber> for UnhardenedIndex {
    type Error = bip32::Error;

    fn try_from(value: ChildNumber) -> Result<Self, Self::Error> {
        match value {
            ChildNumber::Normal { index } => Ok(UnhardenedIndex(index)),
            ChildNumber::Hardened { .. } => {
                Err(bip32::Error::InvalidChildNumberFormat)
            }
        }
    }
}

impl From<UnhardenedIndex> for ChildNumber {
    fn from(idx: UnhardenedIndex) -> Self {
        ChildNumber::Normal { index: idx.0 }
    }
}

/// Index for hardened children derivation; ensures that the wrapped value
/// >= 2^31
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
    Display,
    From,
    StrictEncode,
    StrictDecode,
)]
#[display("{0}'", alt = "{0}h")]
pub struct HardenedIndex(
    #[from(u8)]
    #[from(u16)]
    pub(self) u32,
);

impl ChildIndex for HardenedIndex {
    #[inline]
    fn from_index(index: impl Into<u32>) -> Result<Self, Error> {
        let index = index.into();
        if index >= HARDENED_INDEX_BOUNDARY {
            Ok(Self(index - HARDENED_INDEX_BOUNDARY))
        } else {
            Ok(Self(index))
        }
    }

    #[inline]
    fn index(self) -> Option<u32> {
        Some(self.0)
    }

    #[inline]
    fn index_mut(&mut self) -> Option<&mut u32> {
        Some(&mut self.0)
    }

    #[inline]
    fn is_hardened(&self) -> bool {
        true
    }
}

impl FromStr for HardenedIndex {
    type Err = bip32::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match ChildNumber::from_str(s)? {
            ChildNumber::Normal { .. } => {
                Err(bip32::Error::InvalidChildNumberFormat)
            }
            ChildNumber::Hardened { index } => Ok(Self(index)),
        }
    }
}

impl From<HardenedIndex> for u32 {
    fn from(index: HardenedIndex) -> Self {
        index.0
    }
}

impl TryFrom<ChildNumber> for HardenedIndex {
    type Error = bip32::Error;

    fn try_from(value: ChildNumber) -> Result<Self, Self::Error> {
        match value {
            ChildNumber::Hardened { index } => Ok(HardenedIndex(index)),
            ChildNumber::Normal { .. } => {
                Err(bip32::Error::InvalidChildNumberFormat)
            }
        }
    }
}

impl From<HardenedIndex> for ChildNumber {
    fn from(index: HardenedIndex) -> Self {
        ChildNumber::Hardened { index: index.0 }
    }
}

// -----------------------------------------------------------------------------

#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    From,
    StrictEncode,
    StrictDecode,
)]
pub enum BranchStep {
    #[from(u8)]
    #[from(u16)]
    #[from(UnhardenedIndex)]
    Normal(u32),

    Hardened {
        #[from(HardenedIndex)]
        index: u32,
        xpub_ref: Option<XpubRef>,
    },
}

impl BranchStep {
    #[inline]
    pub fn zero_hardened() -> Self {
        Self::Hardened {
            index: 0,
            xpub_ref: None,
        }
    }

    #[inline]
    pub fn one_hardened() -> Self {
        Self::Hardened {
            index: 1,
            xpub_ref: None,
        }
    }

    #[inline]
    pub fn with_xpub(hardened: HardenedIndex, xpub: XpubRef) -> Self {
        Self::Hardened {
            index: hardened.0,
            xpub_ref: Some(xpub),
        }
    }

    #[inline]
    pub fn xpub_ref(&self) -> Option<&XpubRef> {
        match self {
            BranchStep::Hardened {
                xpub_ref: Some(xpub),
                ..
            } => Some(xpub),
            _ => None,
        }
    }
}

impl ChildIndex for BranchStep {
    fn from_index(index: impl Into<u32>) -> Result<Self, Error> {
        let index = index.into();
        if index >= HARDENED_INDEX_BOUNDARY {
            Ok(BranchStep::Hardened {
                index,
                xpub_ref: None,
            })
        } else {
            Ok(BranchStep::Normal(index))
        }
    }

    fn index(self) -> Option<u32> {
        Some(match self {
            BranchStep::Normal(index) => index,
            BranchStep::Hardened { index, .. } => index,
        })
    }

    #[inline]
    fn index_mut(&mut self) -> Option<&mut u32> {
        Some(match self {
            BranchStep::Normal(ref mut index) => index,
            BranchStep::Hardened { ref mut index, .. } => index,
        })
    }

    fn is_hardened(&self) -> bool {
        match self {
            BranchStep::Normal(_) => false,
            BranchStep::Hardened { .. } => true,
        }
    }
}

impl Display for BranchStep {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            BranchStep::Normal(index) => Display::fmt(index, f),
            BranchStep::Hardened {
                index,
                xpub_ref: None,
            } => {
                Display::fmt(index, f)?;
                f.write_str(if f.alternate() { "h" } else { "'" })
            }
            BranchStep::Hardened {
                index,
                xpub_ref: Some(xpub),
            } => {
                Display::fmt(index, f)?;
                f.write_str(if f.alternate() { "h" } else { "'" })?;
                Display::fmt(xpub, f)
            }
        }
    }
}

impl FromStr for BranchStep {
    type Err = bip32::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('=');
        Ok(match (split.next(), split.next(), split.next()) {
            (Some(s), None, _) => ChildNumber::from_str(s)?.into(),
            (Some(s), Some(xpub), None) => BranchStep::Hardened {
                index: HardenedIndex::from_str(s)?.0,
                xpub_ref: Some(xpub.parse()?),
            },
            _ => Err(bip32::Error::InvalidDerivationPathFormat)?,
        })
    }
}

impl From<BranchStep> for u32 {
    #[inline]
    fn from(value: BranchStep) -> Self {
        match value {
            BranchStep::Normal(index) => index,
            BranchStep::Hardened { index, .. } => index,
        }
    }
}

impl From<ChildNumber> for BranchStep {
    fn from(child_number: ChildNumber) -> Self {
        match child_number {
            ChildNumber::Normal { index } => BranchStep::Normal(index),
            ChildNumber::Hardened { index } => BranchStep::Hardened {
                index,
                xpub_ref: None,
            },
        }
    }
}

impl From<BranchStep> for ChildNumber {
    fn from(value: BranchStep) -> Self {
        match value {
            BranchStep::Normal(index) => ChildNumber::Normal { index },
            BranchStep::Hardened { index, .. } => {
                ChildNumber::Hardened { index }
            }
        }
    }
}

impl TryFrom<BranchStep> for UnhardenedIndex {
    type Error = bip32::Error;

    fn try_from(value: BranchStep) -> Result<Self, Self::Error> {
        match value {
            BranchStep::Normal(index) => Ok(UnhardenedIndex(index)),
            BranchStep::Hardened { index, .. } => {
                Err(bip32::Error::InvalidChildNumber(index))
            }
        }
    }
}

impl TryFrom<BranchStep> for HardenedIndex {
    type Error = bip32::Error;

    fn try_from(value: BranchStep) -> Result<Self, Self::Error> {
        match value {
            BranchStep::Normal(index) => {
                Err(bip32::Error::InvalidChildNumber(index))
            }
            BranchStep::Hardened { index, .. } => Ok(HardenedIndex(index)),
        }
    }
}

#[derive(
    Clone,
    Copy,
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
pub enum TerminalStep {
    #[display("{0}", alt = "{0}h")]
    #[from(u8)]
    #[from(u16)]
    #[from(UnhardenedIndex)]
    Normal(u32),

    #[display("*")]
    WildcardNormal,

    #[display("*'", alt = "*h")]
    WildcardHardened,
}

impl TerminalStep {
    #[inline]
    pub fn is_wildcard(&self) -> bool {
        match self {
            TerminalStep::Normal(_) => false,
            _ => true,
        }
    }
}

impl ChildIndex for TerminalStep {
    #[inline]
    fn from_index(index: impl Into<u32>) -> Result<Self, Error> {
        let index = index.into();
        if index >= HARDENED_INDEX_BOUNDARY {
            Err(bip32::Error::InvalidChildNumber(index))
        } else {
            Ok(TerminalStep::Normal(index))
        }
    }

    #[inline]
    fn index(self) -> Option<u32> {
        match self {
            TerminalStep::Normal(index) => Some(index),
            _ => None,
        }
    }

    fn index_mut(&mut self) -> Option<&mut u32> {
        match self {
            TerminalStep::Normal(ref mut index) => Some(index),
            _ => None,
        }
    }

    #[inline]
    fn is_hardened(&self) -> bool {
        *self == TerminalStep::WildcardHardened
    }
}

impl FromStr for TerminalStep {
    type Err = bip32::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "*" => TerminalStep::WildcardNormal,
            "*'" | "*h" => TerminalStep::WildcardHardened,
            s => UnhardenedIndex::from_str(s)?.into(),
        })
    }
}

impl From<TerminalStep> for u32 {
    #[inline]
    fn from(value: TerminalStep) -> Self {
        match value {
            TerminalStep::Normal(index) => index,
            TerminalStep::WildcardNormal => 0,
            TerminalStep::WildcardHardened => HARDENED_INDEX_BOUNDARY,
        }
    }
}

impl TryFrom<TerminalStep> for UnhardenedIndex {
    type Error = bip32::Error;

    fn try_from(value: TerminalStep) -> Result<Self, Self::Error> {
        match value {
            TerminalStep::Normal(index) => Ok(UnhardenedIndex(index)),
            _ => Err(bip32::Error::InvalidChildNumberFormat),
        }
    }
}

impl TryFrom<ChildNumber> for TerminalStep {
    type Error = bip32::Error;

    fn try_from(value: ChildNumber) -> Result<Self, Self::Error> {
        match value {
            ChildNumber::Normal { index } => Ok(TerminalStep::Normal(index)),
            _ => Err(bip32::Error::InvalidChildNumberFormat),
        }
    }
}

impl TryFrom<TerminalStep> for ChildNumber {
    type Error = bip32::Error;

    fn try_from(value: TerminalStep) -> Result<Self, Self::Error> {
        match value {
            TerminalStep::Normal(index) => Ok(ChildNumber::Normal { index }),
            _ => Err(bip32::Error::InvalidChildNumberFormat),
        }
    }
}

// -----------------------------------------------------------------------------

/// Method-trait that can be implemented by all types able to derive a
/// public key with a given path
pub trait DerivePublicKey {
    fn derive_public_key(
        &self,
        child_index: UnhardenedIndex,
    ) -> bitcoin::PublicKey;
}

/// Extension trait allowing to add more methods to [`DerivationPath`] type
pub trait DerivationPathMaster {
    fn master() -> Self;
    fn is_master(&self) -> bool;
}

impl DerivationPathMaster for DerivationPath {
    /// Returns derivation path for a master key (i.e. empty derivation path)
    fn master() -> DerivationPath {
        vec![].into()
    }

    /// Returns whether derivation path represents master key (i.e. it's length
    /// is empty). True for `m` path.
    fn is_master(&self) -> bool {
        self.into_iter().len() == 0
    }
}

pub trait HardenedNormalSplit {
    fn hardened_normal_split(&self) -> (DerivationPath, Vec<u32>);
}

impl HardenedNormalSplit for DerivationPath {
    fn hardened_normal_split(&self) -> (DerivationPath, Vec<u32>) {
        let mut terminal_path = vec![];
        let branch_path = self
            .into_iter()
            .rev()
            .by_ref()
            .skip_while(|child| {
                if let ChildNumber::Normal { index } = child {
                    terminal_path.push(index);
                    true
                } else {
                    false
                }
            })
            .cloned()
            .collect::<DerivationPath>();
        let branch_path = branch_path.into_iter().rev().cloned().collect();
        let terminal_path = terminal_path.into_iter().rev().cloned().collect();
        (branch_path, terminal_path)
    }
}

// -----------------------------------------------------------------------------

#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    StrictEncode,
    StrictDecode,
)]
// [master_xpub]/branch_path=[branch_xpub]/terminal_path/index_ranges
pub struct DerivationComponents {
    pub master_xpub: ExtendedPubKey,
    pub branch_path: DerivationPath,
    pub branch_xpub: ExtendedPubKey,
    pub terminal_path: Vec<u32>,
    pub index_ranges: Option<Vec<DerivationRange>>,
}

impl DerivationComponents {
    pub fn count(&self) -> u32 {
        match self.index_ranges {
            None => ::std::u32::MAX,
            Some(ref ranges) => {
                ranges.iter().fold(0u32, |sum, range| sum + range.count())
            }
        }
    }

    pub fn derivation_path(&self) -> DerivationPath {
        self.branch_path.extend(self.terminal_path())
    }

    pub fn terminal_path(&self) -> DerivationPath {
        DerivationPath::from_iter(
            self.terminal_path
                .iter()
                .map(|i| ChildNumber::Normal { index: *i }),
        )
    }

    pub fn index_ranges_string(&self) -> String {
        self.index_ranges
            .as_ref()
            .map(|ranges| {
                ranges
                    .iter()
                    .map(DerivationRange::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default()
    }

    pub fn child(&self, child: u32) -> ExtendedPubKey {
        let derivation = self
            .terminal_path()
            .into_child(ChildNumber::Normal { index: child });
        self.branch_xpub
            .derive_pub(&crate::SECP256K1, &derivation)
            .expect("Non-hardened derivation does not fail")
    }

    pub fn derive_public_key(
        &self,
        child_index: UnhardenedIndex,
    ) -> bitcoin::PublicKey {
        self.child(child_index.into()).public_key
    }
}

impl Display for DerivationComponents {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "[{}]", self.master_xpub.fingerprint())?;
        } else {
            write!(f, "[{}]", self.master_xpub)?;
        }
        f.write_str(self.branch_path.to_string().trim_start_matches("m"))?;
        if f.alternate() {
            f.write_str("/")?;
        } else if self.branch_xpub != self.master_xpub {
            write!(f, "=[{}]", self.branch_xpub)?;
        }
        f.write_str(self.terminal_path().to_string().trim_start_matches("m"))?;
        f.write_str("/")?;
        if let Some(_) = self.index_ranges {
            f.write_str(&self.index_ranges_string())
        } else {
            f.write_str("*")
        }
    }
}

#[derive(
    Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error,
)]
#[display(inner)]
pub struct ComponentsParseError(pub String);

impl FromStr for DerivationComponents {
    type Err = ComponentsParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
            static ref RE_DERIVATION: Regex = Regex::new(
                r"(?x)^
                \[(?P<xpub>[xyztuvXYZTUV]pub[1-9A-HJ-NP-Za-km-z]{107,108})\]
                /(?P<deriv>([0-9]{1,10}[h']?)+)
                (/(?P<range>\*|([0-9]{1,10}([,-][0-9]{1,10})*)))?
                $",
            )
            .expect("Regexp expression for `DerivationComponents` is broken");
        }

        let mut split = s.split('=');
        let (branch, terminal) = match (split.next(), split.next(), split.next()) {
            (Some(branch), Some(terminal), None) => (Some(branch), terminal),
            (Some(terminal), None, None) => (None, terminal),
            (None, None, None) => unreachable!(),
            _ => Err(ComponentsParseError(s!("Derivation components string must contain at most two parts separated by `=`")))?
        };

        let caps = if let Some(caps) = RE_DERIVATION.captures(terminal) {
            caps
        } else {
            Err(ComponentsParseError(s!(
                "Wrong composition of derivation components data"
            )))?
        };

        let branch_xpub = ExtendedPubKey::from_slip132_str(
            caps.name("xpub").expect("regexp engine is broken").as_str(),
        )
        .map_err(|err| ComponentsParseError(err.to_string()))?;
        let terminal_path = caps
            .name("deriv")
            .expect("regexp engine is broken")
            .as_str();
        let terminal_path =
            DerivationPath::from_str(&format!("m/{}", terminal_path))
                .map_err(|err| ComponentsParseError(err.to_string()))?;
        let (prefix, terminal_path) = terminal_path.hardened_normal_split();
        if !prefix.as_ref().is_empty() {
            Err(ComponentsParseError(s!(
                "Terminal derivation path must not contain hardened keys"
            )))?;
        }
        let index_ranges = caps.name("range").and_then(|range| {
            let range = range.as_str();
            if range == "*" {
                return None;
            } else {
                Some(
                    range
                        .split(',')
                        .map(|item| {
                            let mut split = item.split('-');
                            let (start, end) =
                                match (split.next(), split.next()) {
                                    (Some(start), Some(end)) => (
                                        start
                                            .parse()
                                            .expect("regexp engine is broken"),
                                        end.parse()
                                            .expect("regexp engine is broken"),
                                    ),
                                    (Some(start), None) => {
                                        let idx: u32 = start
                                            .parse()
                                            .expect("regexp engine is broken");
                                        (idx, idx)
                                    }
                                    _ => unreachable!(),
                                };
                            DerivationRange::from_inner(RangeInclusive::new(
                                start, end,
                            ))
                        })
                        .collect(),
                )
            }
        });

        let (master_xpub, branch_path) = if let Some(caps) =
            branch.and_then(|branch| RE_DERIVATION.captures(branch))
        {
            let master_xpub = ExtendedPubKey::from_slip132_str(
                caps.name("xpub").expect("regexp engine is broken").as_str(),
            )
            .map_err(|err| ComponentsParseError(err.to_string()))?;
            let branch_path = caps
                .name("deriv")
                .expect("regexp engine is broken")
                .as_str();
            let branch_path =
                DerivationPath::from_str(&format!("m/{}", branch_path))
                    .map_err(|err| ComponentsParseError(err.to_string()))?;
            (master_xpub, branch_path)
        } else {
            (
                branch_xpub.clone(),
                DerivationPath::from(Vec::<ChildNumber>::new()),
            )
        };

        Ok(DerivationComponents {
            master_xpub,
            branch_path,
            branch_xpub,
            terminal_path,
            index_ranges,
        })
    }
}

impl MiniscriptKey for DerivationComponents {
    type Hash = Self;

    fn to_pubkeyhash(&self) -> Self::Hash {
        self.clone()
    }
}

// -----------------------------------------------------------------------------

#[derive(Wrapper, Clone, PartialEq, Eq, Hash, Debug, From)]
pub struct DerivationRange(RangeInclusive<u32>);

impl PartialOrd for DerivationRange {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.start().partial_cmp(&other.start()) {
            Some(Ordering::Equal) => self.end().partial_cmp(&other.end()),
            other => other,
        }
    }
}

impl Ord for DerivationRange {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.start().cmp(&other.start()) {
            Ordering::Equal => self.end().cmp(&other.end()),
            other => other,
        }
    }
}

impl DerivationRange {
    pub fn count(&self) -> u32 {
        let inner = self.as_inner();
        inner.end() - inner.start() + 1
    }

    pub fn start(&self) -> u32 {
        *self.as_inner().start()
    }

    pub fn end(&self) -> u32 {
        *self.as_inner().end()
    }
}

impl Display for DerivationRange {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let inner = self.as_inner();
        if inner.start() == inner.end() {
            write!(f, "{}", inner.start())
        } else {
            write!(f, "{}-{}", inner.start(), inner.end())
        }
    }
}

impl StrictEncode for DerivationRange {
    fn strict_encode<E: io::Write>(
        &self,
        mut e: E,
    ) -> Result<usize, strict_encoding::Error> {
        Ok(strict_encode_list!(e; self.start(), self.end()))
    }
}

impl StrictDecode for DerivationRange {
    fn strict_decode<D: io::Read>(
        mut d: D,
    ) -> Result<Self, strict_encoding::Error> {
        Ok(Self::from_inner(RangeInclusive::new(
            u32::strict_decode(&mut d)?,
            u32::strict_decode(&mut d)?,
        )))
    }
}
