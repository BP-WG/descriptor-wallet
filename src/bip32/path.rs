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

use std::convert::TryFrom;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use bitcoin::util::bip32::{self, ChildNumber};
use strict_encoding::{self, StrictDecode, StrictEncode};

use super::{DerivationRangeVec, XpubRef, HARDENED_INDEX_BOUNDARY};

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
    fn from_index(index: impl Into<u32>) -> Result<Self, bip32::Error> {
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
    fn from_index(index: impl Into<u32>) -> Result<Self, bip32::Error> {
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
    Index(u32),

    #[from]
    Range(DerivationRangeVec),

    #[display("*")]
    Wildcard,
}

impl TerminalStep {
    #[inline]
    pub fn is_wildcard(&self) -> bool {
        match self {
            TerminalStep::Index(_) => false,
            _ => true,
        }
    }
}

impl ChildIndex for TerminalStep {
    #[inline]
    fn from_index(index: impl Into<u32>) -> Result<Self, bip32::Error> {
        let index = index.into();
        if index >= HARDENED_INDEX_BOUNDARY {
            Err(bip32::Error::InvalidChildNumber(index))
        } else {
            Ok(TerminalStep::Index(index))
        }
    }

    #[inline]
    fn index(self) -> Option<u32> {
        match self {
            TerminalStep::Index(index) => Some(index),
            _ => None,
        }
    }

    fn index_mut(&mut self) -> Option<&mut u32> {
        match self {
            TerminalStep::Index(ref mut index) => Some(index),
            _ => None,
        }
    }

    #[inline]
    fn is_hardened(&self) -> bool {
        false
    }
}

impl FromStr for TerminalStep {
    type Err = bip32::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "*" => TerminalStep::Wildcard,
            s => UnhardenedIndex::from_str(s)?.into(),
        })
    }
}

impl From<TerminalStep> for u32 {
    #[inline]
    fn from(value: TerminalStep) -> Self {
        match value {
            TerminalStep::Index(index) => index,
            TerminalStep::Range(ranges) => ranges.first_index(),
            TerminalStep::Wildcard => 0,
        }
    }
}

impl TryFrom<TerminalStep> for UnhardenedIndex {
    type Error = bip32::Error;

    fn try_from(value: TerminalStep) -> Result<Self, Self::Error> {
        match value {
            TerminalStep::Index(index) => Ok(UnhardenedIndex(index)),
            _ => Err(bip32::Error::InvalidChildNumberFormat),
        }
    }
}

impl TryFrom<ChildNumber> for TerminalStep {
    type Error = bip32::Error;

    fn try_from(value: ChildNumber) -> Result<Self, Self::Error> {
        match value {
            ChildNumber::Normal { index } => Ok(TerminalStep::Index(index)),
            _ => Err(bip32::Error::InvalidChildNumberFormat),
        }
    }
}

impl TryFrom<TerminalStep> for ChildNumber {
    type Error = bip32::Error;

    fn try_from(value: TerminalStep) -> Result<Self, Self::Error> {
        match value {
            TerminalStep::Index(index) => Ok(ChildNumber::Normal { index }),
            _ => Err(bip32::Error::InvalidChildNumberFormat),
        }
    }
}
