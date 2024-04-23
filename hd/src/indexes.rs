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

use std::cmp::Ordering;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use bitcoin::util::bip32::{self, ChildNumber, Error};

use super::{IndexRangeList, XpubRef, HARDENED_INDEX_BOUNDARY};
use crate::IndexRange;

// TODO: Implement iterator methods

/// Trait defining common API for different types of indexes which may be
/// present in a certain derivation path segment: hardened, unhardened, mixed.
pub trait SegmentIndexes
where
    Self: Sized + Eq + Ord + Clone,
{
    /// Constructs derivation path segment with index equal to zero
    fn zero() -> Self;

    /// Constructs derivation path segment with index equal to one
    fn one() -> Self;

    /// Constructs derivation path segment with index equal to maximum value
    fn largest() -> Self;

    /// Counts number of derivation indexes in this derivation path segment
    fn count(&self) -> usize;

    /// Detects if a given index may be used at this derivation segment
    fn contains(&self, index: u32) -> bool;

    /// Constructs derivation path segment with specific index.
    ///
    /// Index is always a value in range of `0..`[`HARDENED_INDEX_BOUNDARY`]
    fn from_index(index: impl Into<u32>) -> Result<Self, bip32::Error>;

    /// Returns index representation of this derivation path segment. If
    /// derivation path segment contains multiple indexes, returns the value of
    /// the first one.
    ///
    /// Index is always a value in range of `0..`[`HARDENED_INDEX_BOUNDARY`]
    fn first_index(&self) -> u32;

    /// Returns index representation of this derivation path segment. If
    /// derivation path segment contains multiple indexes, returns the value of
    /// the last one; otherwise equal to [`SegmentIndexes::first_index`];
    ///
    /// Index is always a value in range of `0..`[`HARDENED_INDEX_BOUNDARY`]
    #[inline]
    fn last_index(&self) -> u32 { self.first_index() }

    /// Constructs derivation path segment with specific derivation value, which
    /// for normal indexes must lie in range `0..`[`HARDENED_INDEX_BOUNDARY`]
    /// and for hardened in range of [`HARDENED_INDEX_BOUNDARY`]`..=u32::MAX`
    fn from_derivation_value(value: u32) -> Result<Self, bip32::Error>;

    /// Returns value used during derivation, which for normal indexes must lie
    /// in range `0..`[`HARDENED_INDEX_BOUNDARY`] and for hardened in range
    /// of [`HARDENED_INDEX_BOUNDARY`]`..=u32::MAX`
    fn first_derivation_value(&self) -> u32;

    /// Returns value used during derivation, which for normal indexes must lie
    /// in range `0..`[`HARDENED_INDEX_BOUNDARY`] and for hardened in range
    /// of [`HARDENED_INDEX_BOUNDARY`]`..=u32::MAX`.
    ///
    /// If the path segment consist of the single index value, this function is
    /// equal to [`SegmentIndexes::first_derivation_value`]
    #[inline]
    fn last_derivation_value(&self) -> u32 { self.first_derivation_value() }

    /// Increases the index on one step; fails if the index value is already
    /// maximum value - or if multiple indexes are present at the path segment
    fn checked_inc(&self) -> Option<Self> { self.checked_add(1u8) }

    /// Decreases the index on one step; fails if the index value is already
    /// minimum value - or if multiple indexes are present at the path segment
    fn checked_dec(&self) -> Option<Self> { self.checked_sub(1u8) }

    /// Mutates the self by increasing the index on one step; fails if the index
    /// value is already maximum value - or if multiple indexes are present at
    /// the path segment
    fn checked_inc_assign(&mut self) -> Option<u32> { self.checked_add_assign(1u8) }

    /// Mutates the self by decreasing the index on one step; fails if the index
    /// value is already maximum value - or if multiple indexes are present at
    /// the path segment
    fn checked_dec_assign(&mut self) -> Option<u32> { self.checked_sub_assign(1u8) }

    /// Adds value the index; fails if the index value overflow happens - or if
    /// multiple indexes are present at the path segment
    fn checked_add(&self, add: impl Into<u32>) -> Option<Self> {
        let mut res = self.clone();
        res.checked_add_assign(add)?;
        Some(res)
    }

    /// Subtracts value the index; fails if the index value overflow happens -
    /// or if multiple indexes are present at the path segment
    fn checked_sub(&self, sub: impl Into<u32>) -> Option<Self> {
        let mut res = self.clone();
        res.checked_sub_assign(sub)?;
        Some(res)
    }

    /// Mutates the self by adding value the index; fails if the index value
    /// overflow happens - or if multiple indexes are present at the path
    /// segment
    fn checked_add_assign(&mut self, add: impl Into<u32>) -> Option<u32>;

    /// Mutates the self by subtracting value the index; fails if the index
    /// value overflow happens - or if multiple indexes are present at the
    /// path segment
    fn checked_sub_assign(&mut self, sub: impl Into<u32>) -> Option<u32>;

    /// Detects whether path segment uses hardened index(es)
    fn is_hardened(&self) -> bool;
}

fn checked_add_assign(index: &mut u32, add: impl Into<u32>) -> Option<u32> {
    let add: u32 = add.into();
    *index = index.checked_add(add)?;
    if *index >= HARDENED_INDEX_BOUNDARY {
        return None;
    }
    Some(*index)
}

fn checked_sub_assign(index: &mut u32, sub: impl Into<u32>) -> Option<u32> {
    let sub: u32 = sub.into();
    *index = index.checked_sub(sub)?;
    Some(*index)
}

// -----------------------------------------------------------------------------

impl SegmentIndexes for ChildNumber {
    #[inline]
    fn zero() -> Self { ChildNumber::Normal { index: 0 } }

    #[inline]
    fn one() -> Self { ChildNumber::Normal { index: 0 } }

    #[inline]
    fn largest() -> Self {
        ChildNumber::Hardened {
            index: HARDENED_INDEX_BOUNDARY - 1,
        }
    }

    #[inline]
    fn count(&self) -> usize { 1 }

    #[inline]
    fn contains(&self, i: u32) -> bool {
        match self {
            ChildNumber::Normal { index } => *index == i,
            ChildNumber::Hardened { index } => *index + HARDENED_INDEX_BOUNDARY == i,
        }
    }

    #[inline]
    fn from_index(index: impl Into<u32>) -> Result<Self, bip32::Error> {
        let index = index.into();
        if index >= HARDENED_INDEX_BOUNDARY {
            Err(bip32::Error::InvalidChildNumber(index))
        } else {
            Ok(ChildNumber::Normal { index })
        }
    }

    /// Panics since here we can't distinguish between hardened and non-hardened
    /// indexes.
    // #[deprecated(note = "use ChildNumber match instead")]
    fn first_index(&self) -> u32 { panic!("method has no meaning for ChildNumber") }

    #[inline]
    fn from_derivation_value(value: u32) -> Result<Self, bip32::Error> {
        Ok(ChildNumber::from(value))
    }

    #[inline]
    fn first_derivation_value(&self) -> u32 { (*self).into() }

    #[inline]
    fn checked_add_assign(&mut self, add: impl Into<u32>) -> Option<u32> {
        match self {
            ChildNumber::Normal { index } => checked_add_assign(index, add),
            ChildNumber::Hardened { index } => checked_add_assign(index, add),
        }
    }

    #[inline]
    fn checked_sub_assign(&mut self, sub: impl Into<u32>) -> Option<u32> {
        match self {
            ChildNumber::Normal { index } => checked_sub_assign(index, sub),
            ChildNumber::Hardened { index } => checked_sub_assign(index, sub),
        }
    }

    #[inline]
    fn is_hardened(&self) -> bool { !self.is_normal() }
}

/// normal derivation index {_0} met when a hardened index was required.
#[derive(
    Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Default, Display, From, Error
)]
#[display(doc_comments)]
pub struct HardenedIndexExpected(pub UnhardenedIndex);

/// hardened derivation index {_0} met when a normal (unhardened) index was
/// required.
#[derive(
    Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Default, Display, From, Error
)]
#[display(doc_comments)]
pub struct UnhardenedIndexExpected(pub HardenedIndex);

/// Index for unhardened children derivation; ensures that the inner value
/// is always < 2^31
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(
    Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Default, Display, From
)]
#[display(inner)]
pub struct UnhardenedIndex(
    #[from(u8)]
    #[from(u16)]
    u32,
);

impl PartialEq<u8> for UnhardenedIndex {
    fn eq(&self, other: &u8) -> bool { self.0 == *other as u32 }
}

impl PartialEq<u16> for UnhardenedIndex {
    fn eq(&self, other: &u16) -> bool { self.0 == *other as u32 }
}

impl PartialOrd<u8> for UnhardenedIndex {
    fn partial_cmp(&self, other: &u8) -> Option<Ordering> { self.0.partial_cmp(&(*other as u32)) }
}

impl PartialOrd<u16> for UnhardenedIndex {
    fn partial_cmp(&self, other: &u16) -> Option<Ordering> { self.0.partial_cmp(&(*other as u32)) }
}

impl From<&UnhardenedIndex> for UnhardenedIndex {
    fn from(index: &UnhardenedIndex) -> Self { *index }
}

impl SegmentIndexes for UnhardenedIndex {
    #[inline]
    fn zero() -> Self { UnhardenedIndex(0) }

    #[inline]
    fn one() -> Self { UnhardenedIndex(1) }

    #[inline]
    fn largest() -> Self { UnhardenedIndex(HARDENED_INDEX_BOUNDARY - 1) }

    #[inline]
    fn count(&self) -> usize { 1 }

    #[inline]
    fn contains(&self, index: u32) -> bool { self.0 == index }

    #[inline]
    fn from_index(index: impl Into<u32>) -> Result<Self, bip32::Error> {
        let index = index.into();
        if index >= HARDENED_INDEX_BOUNDARY {
            Err(bip32::Error::InvalidChildNumber(index))
        } else {
            Ok(Self(index))
        }
    }

    /// Returns unhardened index number.
    #[inline]
    fn first_index(&self) -> u32 { self.0 }

    #[inline]
    fn from_derivation_value(value: u32) -> Result<Self, bip32::Error> { Self::from_index(value) }

    #[inline]
    fn first_derivation_value(&self) -> u32 { self.first_index() }

    #[inline]
    fn checked_add_assign(&mut self, add: impl Into<u32>) -> Option<u32> {
        checked_add_assign(&mut self.0, add)
    }

    #[inline]
    fn checked_sub_assign(&mut self, sub: impl Into<u32>) -> Option<u32> {
        checked_sub_assign(&mut self.0, sub)
    }

    #[inline]
    fn is_hardened(&self) -> bool { false }
}

impl FromStr for UnhardenedIndex {
    type Err = bip32::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        UnhardenedIndex::from_index(
            u32::from_str(s).map_err(|_| bip32::Error::InvalidChildNumberFormat)?,
        )
    }
}

impl TryFrom<ChildNumber> for UnhardenedIndex {
    type Error = UnhardenedIndexExpected;

    fn try_from(value: ChildNumber) -> Result<Self, Self::Error> {
        match value {
            ChildNumber::Normal { index } => Ok(UnhardenedIndex(index)),
            ChildNumber::Hardened { index } => Err(UnhardenedIndexExpected(HardenedIndex(index))),
        }
    }
}

impl From<UnhardenedIndex> for ChildNumber {
    fn from(idx: UnhardenedIndex) -> Self { ChildNumber::Normal { index: idx.0 } }
}

/// Index for hardened children derivation; ensures that the index always >=
/// 2^31.
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(
    Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default, Display, From
)]
#[display("{0}h", alt = "{0}'")]
pub struct HardenedIndex(
    /// The inner index value; always reduced by [`HARDENED_INDEX_BOUNDARY`]
    #[from(u8)]
    #[from(u16)]
    pub(crate) u32,
);

impl PartialEq<u8> for HardenedIndex {
    fn eq(&self, other: &u8) -> bool { self.0 == *other as u32 }
}

impl PartialEq<u16> for HardenedIndex {
    fn eq(&self, other: &u16) -> bool { self.0 == *other as u32 }
}

impl PartialOrd<u8> for HardenedIndex {
    fn partial_cmp(&self, other: &u8) -> Option<Ordering> { self.0.partial_cmp(&(*other as u32)) }
}

impl PartialOrd<u16> for HardenedIndex {
    fn partial_cmp(&self, other: &u16) -> Option<Ordering> { self.0.partial_cmp(&(*other as u32)) }
}

impl SegmentIndexes for HardenedIndex {
    #[inline]
    fn zero() -> Self { HardenedIndex(0) }

    #[inline]
    fn one() -> Self { HardenedIndex(1) }

    #[inline]
    fn largest() -> Self { HardenedIndex(HARDENED_INDEX_BOUNDARY - 1) }

    #[inline]
    fn count(&self) -> usize { 1 }

    #[inline]
    fn contains(&self, index: u32) -> bool { self.0 == index }

    #[inline]
    fn from_index(index: impl Into<u32>) -> Result<Self, bip32::Error> {
        let index = index.into();
        if index >= HARDENED_INDEX_BOUNDARY {
            Ok(Self(index - HARDENED_INDEX_BOUNDARY))
        } else {
            Ok(Self(index))
        }
    }

    /// Returns hardened index number offset by [`HARDENED_INDEX_BOUNDARY`]
    /// (i.e. zero-based).
    #[inline]
    fn first_index(&self) -> u32 { self.0 }

    #[inline]
    fn from_derivation_value(value: u32) -> Result<Self, bip32::Error> {
        if value < HARDENED_INDEX_BOUNDARY {
            return Err(bip32::Error::InvalidChildNumber(value));
        }
        Ok(Self(value - HARDENED_INDEX_BOUNDARY))
    }

    #[inline]
    fn first_derivation_value(&self) -> u32 { self.0 + HARDENED_INDEX_BOUNDARY }

    #[inline]
    fn checked_add_assign(&mut self, add: impl Into<u32>) -> Option<u32> {
        checked_add_assign(&mut self.0, add)
    }

    #[inline]
    fn checked_sub_assign(&mut self, sub: impl Into<u32>) -> Option<u32> {
        checked_sub_assign(&mut self.0, sub)
    }

    #[inline]
    fn is_hardened(&self) -> bool { true }
}

impl FromStr for HardenedIndex {
    type Err = bip32::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match ChildNumber::from_str(s)? {
            ChildNumber::Normal { .. } => Err(bip32::Error::InvalidChildNumberFormat),
            ChildNumber::Hardened { index } => Ok(Self(index)),
        }
    }
}

impl TryFrom<ChildNumber> for HardenedIndex {
    type Error = HardenedIndexExpected;

    fn try_from(value: ChildNumber) -> Result<Self, Self::Error> {
        match value {
            ChildNumber::Hardened { index } => Ok(HardenedIndex(index)),
            ChildNumber::Normal { index } => Err(HardenedIndexExpected(UnhardenedIndex(index))),
        }
    }
}

impl From<HardenedIndex> for ChildNumber {
    fn from(index: HardenedIndex) -> Self { ChildNumber::Hardened { index: index.0 } }
}

// -----------------------------------------------------------------------------

/// Derivation segment for the account part of the derivation path as defined by
/// LNPBP-32 standard
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum AccountStep {
    /// Derivation segment is defined by a single unhardened index
    #[from(u8)]
    #[from(u16)]
    #[from]
    Normal(UnhardenedIndex),

    /// Derivation segment is defined by a hardened index
    Hardened {
        /// Hardened derivation 0-based index value (i.e. offset on
        /// [`HARDENED_INDEX_BOUNDARY`]
        index: HardenedIndex,

        /// Xpub reference which may be is present at this segment (see
        /// [`XpubRef`])
        xpub_ref: XpubRef,
    },
}

impl AccountStep {
    /// Constructs [`AccountStep`] with [`HardenedIndex`] and no
    /// extended public key reference
    #[inline]
    pub fn hardened(index: HardenedIndex) -> Self {
        Self::Hardened {
            index,
            xpub_ref: XpubRef::Unknown,
        }
    }

    /// Constructs [`AccountStep`] with u16 value interpreted as a
    /// [`HardenedIndex::from`] parameter – and no extended public key
    /// reference
    #[inline]
    pub fn hardened_index(index: u16) -> Self {
        Self::Hardened {
            index: HardenedIndex::from(index),
            xpub_ref: XpubRef::Unknown,
        }
    }

    /// Constructs [`AccountStep`] with [`HardenedIndex`] and given
    /// extended public key reference
    #[inline]
    pub fn with_xpub(hardened: HardenedIndex, xpub_ref: XpubRef) -> Self {
        Self::Hardened {
            index: hardened,
            xpub_ref,
        }
    }

    /// Returns extended public key reference
    #[inline]
    pub fn xpub_ref(&self) -> Option<XpubRef> {
        match self {
            AccountStep::Hardened { xpub_ref, .. } => Some(*xpub_ref),
            _ => None,
        }
    }

    /// Returns [`HardenedIndex`] if the step is hardened, or `None` otherwise.
    #[inline]
    pub fn to_hardened(&self) -> Option<HardenedIndex> {
        match self {
            AccountStep::Hardened { index, .. } => Some(*index),
            _ => None,
        }
    }

    /// Returns [`UnhardenedIndex`] if the step is not hardened, or `None`
    /// otherwise.
    #[inline]
    pub fn to_unhardened(&self) -> Option<UnhardenedIndex> {
        match self {
            AccountStep::Normal(index) => Some(*index),
            _ => None,
        }
    }
}

impl SegmentIndexes for AccountStep {
    #[inline]
    fn zero() -> Self { AccountStep::hardened(HardenedIndex::zero()) }

    #[inline]
    fn one() -> Self { AccountStep::hardened(HardenedIndex::one()) }

    #[inline]
    fn largest() -> Self { AccountStep::hardened(HardenedIndex::largest()) }

    #[inline]
    fn count(&self) -> usize { 1 }

    #[inline]
    fn contains(&self, i: u32) -> bool {
        match self {
            AccountStep::Normal(index) => index.contains(i),
            AccountStep::Hardened { index, .. } => index.contains(i | HARDENED_INDEX_BOUNDARY),
        }
    }

    fn from_index(index: impl Into<u32>) -> Result<Self, bip32::Error> {
        let index = index.into();
        Ok(UnhardenedIndex::from_index(index)
            .map(Self::Normal)
            .unwrap_or_else(|_| {
                Self::hardened(
                    HardenedIndex::from_index(index)
                        .expect("index is either hardened or unhardened"),
                )
            }))
    }

    #[inline]
    fn first_index(&self) -> u32 {
        match self {
            AccountStep::Normal(index) => SegmentIndexes::first_index(index),
            AccountStep::Hardened { index, .. } => SegmentIndexes::first_index(index),
        }
    }

    #[inline]
    fn from_derivation_value(value: u32) -> Result<Self, bip32::Error> {
        ChildNumber::from_derivation_value(value)
            .map(AccountStep::try_from)
            .and_then(|res| res)
    }

    #[inline]
    fn first_derivation_value(&self) -> u32 {
        match self {
            AccountStep::Normal(index) => index.first_derivation_value(),
            AccountStep::Hardened { index, .. } => index.first_derivation_value(),
        }
    }

    #[inline]
    fn checked_add_assign(&mut self, add: impl Into<u32>) -> Option<u32> {
        match self {
            AccountStep::Normal(index) => index.checked_add_assign(add),
            AccountStep::Hardened { index, .. } => index.checked_add_assign(add),
        }
    }

    #[inline]
    fn checked_sub_assign(&mut self, sub: impl Into<u32>) -> Option<u32> {
        match self {
            AccountStep::Normal(index) => index.checked_sub_assign(sub),
            AccountStep::Hardened { index, .. } => index.checked_sub_assign(sub),
        }
    }

    #[inline]
    fn is_hardened(&self) -> bool {
        match self {
            AccountStep::Normal { .. } => false,
            AccountStep::Hardened { .. } => true,
        }
    }
}

impl Display for AccountStep {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            AccountStep::Normal(index) => Display::fmt(index, f),
            AccountStep::Hardened {
                index,
                xpub_ref: XpubRef::Unknown,
            } => Display::fmt(index, f),
            AccountStep::Hardened { index, xpub_ref } => {
                Display::fmt(index, f)?;
                f.write_str("=")?;
                Display::fmt(xpub_ref, f)
            }
        }
    }
}

impl FromStr for AccountStep {
    type Err = bip32::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('=');
        Ok(match (split.next(), split.next(), split.next()) {
            (Some(s), None, _) => ChildNumber::from_str(s)?.try_into()?,
            (Some(s), Some(xpub), None) => AccountStep::Hardened {
                index: HardenedIndex::from_str(s)?,
                xpub_ref: xpub.parse()?,
            },
            _ => return Err(bip32::Error::InvalidDerivationPathFormat),
        })
    }
}

impl TryFrom<ChildNumber> for AccountStep {
    type Error = bip32::Error;

    /// Since [`ChildNumber`] does not provide API guarantees of the index
    /// values to be in range, we need to re-test them here
    fn try_from(child_number: ChildNumber) -> Result<Self, Self::Error> {
        Ok(match child_number {
            ChildNumber::Normal { index } => {
                AccountStep::Normal(UnhardenedIndex::from_index(index)?)
            }
            ChildNumber::Hardened { index } => {
                AccountStep::hardened(HardenedIndex::from_index(index)?)
            }
        })
    }
}

impl From<AccountStep> for ChildNumber {
    fn from(value: AccountStep) -> Self { ChildNumber::from(&value) }
}

impl From<&AccountStep> for ChildNumber {
    fn from(value: &AccountStep) -> Self {
        match value {
            AccountStep::Normal(index) => ChildNumber::Normal {
                index: index.first_index(),
            },
            AccountStep::Hardened { index, .. } => ChildNumber::Hardened {
                index: index.first_index(),
            },
        }
    }
}

impl From<HardenedIndex> for AccountStep {
    #[inline]
    fn from(index: HardenedIndex) -> Self { AccountStep::hardened(index) }
}

impl TryFrom<AccountStep> for UnhardenedIndex {
    type Error = bip32::Error;

    fn try_from(value: AccountStep) -> Result<Self, Self::Error> {
        match value {
            AccountStep::Normal(index) => Ok(index),
            AccountStep::Hardened { index, .. } => {
                Err(bip32::Error::InvalidChildNumber(index.first_index()))
            }
        }
    }
}

impl TryFrom<AccountStep> for HardenedIndex {
    type Error = bip32::Error;

    fn try_from(value: AccountStep) -> Result<Self, Self::Error> {
        match value {
            AccountStep::Normal(index) => {
                Err(bip32::Error::InvalidChildNumber(index.first_index()))
            }
            AccountStep::Hardened { index, .. } => Ok(index),
        }
    }
}

/// Derivation segment for the terminal part of the derivation path as defined
/// by LNPBP-32 standard
// TODO: Move serde to `TerminalPath` using FromStrDisplay once it will be present
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, From)]
pub enum TerminalStep {
    /// Specific unhardened index
    #[from]
    #[from(u8)]
    #[from(u16)]
    #[display(inner)]
    Index(UnhardenedIndex),

    /// Range of unhardened indexes
    #[from]
    #[display(inner)]
    Range(IndexRangeList<UnhardenedIndex>),

    /// Wildcard implying full range of unhardened indexes
    #[display("*")]
    Wildcard,
}

impl TerminalStep {
    /// Convenience constructor for creating ranged values
    #[inline]
    pub fn range(start: impl Into<UnhardenedIndex>, end: impl Into<UnhardenedIndex>) -> Self {
        TerminalStep::Range(IndexRangeList::from(IndexRange::with(
            start.into(),
            end.into(),
        )))
    }
}

impl SegmentIndexes for TerminalStep {
    #[inline]
    fn zero() -> Self { TerminalStep::Index(UnhardenedIndex::zero()) }

    #[inline]
    fn one() -> Self { TerminalStep::Index(UnhardenedIndex::one()) }

    #[inline]
    fn largest() -> Self { TerminalStep::Index(UnhardenedIndex::largest()) }

    #[inline]
    fn count(&self) -> usize {
        match self {
            TerminalStep::Index(_) => 1,
            TerminalStep::Range(rng) => rng.count(),
            TerminalStep::Wildcard => HARDENED_INDEX_BOUNDARY as usize,
        }
    }

    #[inline]
    fn contains(&self, index: u32) -> bool {
        match self {
            TerminalStep::Index(i) => i.first_index() == index,
            TerminalStep::Range(range) => range.contains(index),
            TerminalStep::Wildcard => true,
        }
    }

    #[inline]
    fn from_index(index: impl Into<u32>) -> Result<Self, bip32::Error> {
        UnhardenedIndex::from_index(index).map(TerminalStep::Index)
    }

    #[inline]
    fn first_index(&self) -> u32 {
        match self {
            TerminalStep::Index(index) => index.first_index(),
            TerminalStep::Range(range) => range.first_index(),
            _ => 0,
        }
    }

    #[inline]
    fn last_index(&self) -> u32 {
        match self {
            TerminalStep::Index(index) => index.last_index(),
            TerminalStep::Range(range) => range.last_index(),
            _ => HARDENED_INDEX_BOUNDARY - 1,
        }
    }

    #[inline]
    fn from_derivation_value(value: u32) -> Result<Self, Error> {
        UnhardenedIndex::from_derivation_value(value).map(TerminalStep::Index)
    }

    #[inline]
    fn first_derivation_value(&self) -> u32 {
        match self {
            TerminalStep::Index(index) => index.first_derivation_value(),
            TerminalStep::Range(range) => range.first_derivation_value(),
            TerminalStep::Wildcard => 0,
        }
    }

    #[inline]
    fn last_derivation_value(&self) -> u32 {
        match self {
            TerminalStep::Index(index) => index.last_derivation_value(),
            TerminalStep::Range(range) => range.last_derivation_value(),
            TerminalStep::Wildcard => HARDENED_INDEX_BOUNDARY - 1,
        }
    }

    #[inline]
    fn checked_add_assign(&mut self, add: impl Into<u32>) -> Option<u32> {
        match self {
            TerminalStep::Index(index) => index.checked_add_assign(add),
            TerminalStep::Range(_) => None,
            TerminalStep::Wildcard => None,
        }
    }

    #[inline]
    fn checked_sub_assign(&mut self, sub: impl Into<u32>) -> Option<u32> {
        match self {
            TerminalStep::Index(index) => index.checked_sub_assign(sub),
            TerminalStep::Range(_) => None,
            TerminalStep::Wildcard => None,
        }
    }

    #[inline]
    fn is_hardened(&self) -> bool { false }
}

impl FromStr for TerminalStep {
    type Err = bip32::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "*" => TerminalStep::Wildcard,
            s if s.contains(&['-', ',', ';'][..]) => IndexRangeList::from_str(s)?.into(),
            s => UnhardenedIndex::from_str(s)?.into(),
        })
    }
}

impl TryFrom<TerminalStep> for UnhardenedIndex {
    type Error = bip32::Error;

    fn try_from(value: TerminalStep) -> Result<Self, Self::Error> {
        match value {
            TerminalStep::Index(index) => Ok(index),
            _ => Err(bip32::Error::InvalidChildNumberFormat),
        }
    }
}

impl TryFrom<ChildNumber> for TerminalStep {
    type Error = bip32::Error;

    fn try_from(value: ChildNumber) -> Result<Self, Self::Error> {
        match value {
            ChildNumber::Normal { index } => {
                Ok(TerminalStep::Index(UnhardenedIndex::from_index(index)?))
            }
            _ => Err(bip32::Error::InvalidChildNumberFormat),
        }
    }
}

impl TryFrom<TerminalStep> for ChildNumber {
    type Error = bip32::Error;

    fn try_from(value: TerminalStep) -> Result<Self, Self::Error> {
        match value {
            TerminalStep::Index(index) => Ok(ChildNumber::Normal {
                index: index.first_index(),
            }),
            _ => Err(bip32::Error::InvalidChildNumberFormat),
        }
    }
}
