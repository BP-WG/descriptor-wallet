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

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::ops::RangeInclusive;
use std::str::FromStr;

use amplify::Wrapper;
use bitcoin::util::bip32;
use strict_encoding::{self, StrictDecode, StrictEncode};

use crate::SegmentIndexes;

// TODO: Implement iterator methods

/// Multiple index ranges (in form `a..b, c..d`) as it can be present in the
/// derivation path segment according to BOP-88 and LNPBP-32. The range is
/// always inclusive.
///
/// The type is guaranteed to have at least one index in the range and at least
/// one range element. It also guarantees that all individual ranges are
/// disjoint.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
pub struct IndexRangeList<Index>(#[from] BTreeSet<IndexRange<Index>>)
where
    Index: SegmentIndexes;

impl<Index> IndexRangeList<Index>
where
    Index: SegmentIndexes,
{
    /// Adds new index range to the list of index ranges present at some
    /// derivation path segment.
    ///
    /// Checks if the added range at least partially intersects with other
    /// existing ranges and errors in this case.
    pub fn insert(&mut self, range: IndexRange<Index>) -> Result<(), bip32::Error> {
        for elem in &self.0 {
            if elem.does_intersect(&range) {
                return Err(bip32::Error::InvalidDerivationPathFormat);
            }
        }
        self.0.insert(range);
        Ok(())
    }

    /// Remove index range from the list; returning `true` if the range was
    /// present in the list. Removes only full ranges and not
    /// partially-intersected range.
    #[inline]
    pub fn remove(&mut self, range: &IndexRange<Index>) -> bool { self.0.remove(range) }

    /// Counts number of disjoint ranges withing the list
    #[inline]
    pub fn range_count(&self) -> usize { self.0.len() }

    /// Returns the first range from the list of ranges.
    #[inline]
    pub fn first_range(&self) -> &IndexRange<Index> {
        self.0
            .iter()
            .next()
            .expect("IndexRangeList guarantees are broken")
    }

    /// Returns the last range from the list of ranges. If the list contain only
    /// one range the function will return the same value as
    /// [`IndexRangeList::first_range`]
    #[inline]
    pub fn last_range(&self) -> &IndexRange<Index> {
        self.0
            .iter()
            .last()
            .expect("IndexRangeList guarantees are broken")
    }
}

impl<Index> SegmentIndexes for IndexRangeList<Index>
where
    Index: SegmentIndexes,
{
    #[inline]
    fn zero() -> Self { Self(bset![IndexRange::zero()]) }

    #[inline]
    fn one() -> Self { Self(bset![IndexRange::one()]) }

    #[inline]
    fn largest() -> Self { Self(bset![IndexRange::largest()]) }

    #[inline]
    fn count(&self) -> usize { self.0.iter().map(IndexRange::count).sum() }

    #[inline]
    fn from_index(index: impl Into<u32>) -> Result<Self, bip32::Error> {
        Ok(Self(bset![IndexRange::from_index(index)?]))
    }

    #[inline]
    fn first_index(&self) -> u32 { self.first_range().first_index() }

    #[inline]
    fn last_index(&self) -> u32 { self.last_range().last_index() }

    #[inline]
    fn from_derivation_value(value: u32) -> Result<Self, bip32::Error> {
        Ok(Self(bset![IndexRange::from_derivation_value(value)?]))
    }

    #[inline]
    fn first_derivation_value(&self) -> u32 { self.first_range().first_derivation_value() }

    #[inline]
    fn last_derivation_value(&self) -> u32 { self.last_range().last_derivation_value() }

    #[inline]
    fn checked_add_assign(&mut self, _: impl Into<u32>) -> Option<u32> { None }

    #[inline]
    fn checked_sub_assign(&mut self, _: impl Into<u32>) -> Option<u32> { None }

    #[inline]
    fn is_hardened(&self) -> bool { self.first_range().is_hardened() }
}

impl<Index> StrictEncode for IndexRangeList<Index>
where
    Index: SegmentIndexes + StrictEncode,
    BTreeSet<IndexRange<Index>>: StrictEncode,
{
    #[inline]
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, strict_encoding::Error> {
        self.0.strict_encode(e)
    }
}

impl<Index> StrictDecode for IndexRangeList<Index>
where
    Index: SegmentIndexes + StrictDecode,
    BTreeSet<IndexRange<Index>>: StrictDecode,
{
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, strict_encoding::Error> {
        let set = BTreeSet::<IndexRange<Index>>::strict_decode(d)?;
        if set.is_empty() {
            return Err(strict_encoding::Error::DataIntegrityError(s!(
                "IndexRangeList when deserialized must has at least one element"
            )));
        }
        let mut list = IndexRangeList(bset![]);
        for elem in set {
            list.insert(elem).map_err(|_| {
                strict_encoding::Error::DataIntegrityError(s!(
                    "IndexRangeList elements must be disjoint ranges"
                ))
            })?;
        }
        Ok(list)
    }
}

impl<Index> From<IndexRange<Index>> for IndexRangeList<Index>
where
    Index: SegmentIndexes,
{
    fn from(range: IndexRange<Index>) -> Self { Self(bset![range]) }
}

impl<Index> TryFrom<Vec<IndexRange<Index>>> for IndexRangeList<Index>
where
    Index: SegmentIndexes,
{
    type Error = bip32::Error;

    fn try_from(value: Vec<IndexRange<Index>>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(bip32::Error::InvalidDerivationPathFormat);
        }
        let mut list = IndexRangeList(bset![]);
        for range in value {
            list.insert(range)?;
        }
        Ok(list)
    }
}

impl<Index> Display for IndexRangeList<Index>
where
    Index: SegmentIndexes + Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(
            &self
                .0
                .iter()
                .map(IndexRange::to_string)
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

impl<Index> FromStr for IndexRangeList<Index>
where
    Index: SegmentIndexes + FromStr,
    bip32::Error: From<<Index as FromStr>::Err>,
{
    type Err = bip32::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut list = Self(bset![]);
        for item in s.split(',') {
            list.insert(IndexRange::from_str(item)?)?;
        }
        Ok(list)
    }
}

/// Range of derivation indexes (in form `n..m`) as it can be present in the
/// derivation path terminal segment according to BIP-88 and LNPBP-32. The range
/// is always inclusive.
///
/// The type is guaranteed to have at least one index in the range.
#[derive(Wrapper, Clone, PartialEq, Eq, Hash, Debug, From)]
pub struct IndexRange<Index>(RangeInclusive<Index>)
where
    Index: SegmentIndexes;

impl<Index> PartialOrd for IndexRange<Index>
where
    Index: SegmentIndexes,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.first_index().partial_cmp(&other.first_index()) {
            Some(Ordering::Equal) => self.last_index().partial_cmp(&other.last_index()),
            other => other,
        }
    }
}

impl<Index> Ord for IndexRange<Index>
where
    Index: SegmentIndexes,
{
    fn cmp(&self, other: &Self) -> Ordering {
        match self.first_index().cmp(&other.first_index()) {
            Ordering::Equal => self.last_index().cmp(&other.last_index()),
            other => other,
        }
    }
}

impl<Index> IndexRange<Index>
where
    Index: SegmentIndexes,
{
    /// Constructs index range from a single index.
    pub fn new(index: Index) -> Self { Self(RangeInclusive::new(index.clone(), index)) }

    /// Constructs index range from two indexes. If `end` < `start` the order
    /// of indexes is reversed
    pub fn with(start: Index, end: Index) -> Self {
        if end < start {
            Self(RangeInclusive::new(end, start))
        } else {
            Self(RangeInclusive::new(start, end))
        }
    }

    /// Detects whether two index ranges share common indexes (i.e. intersect)
    #[inline]
    pub fn does_intersect(&self, other: &IndexRange<Index>) -> bool {
        self.first_index() <= other.last_index() && other.first_index() <= self.last_index()
    }
}

impl<Index> SegmentIndexes for IndexRange<Index>
where
    Index: SegmentIndexes,
{
    #[inline]
    fn zero() -> Self { IndexRange(Index::zero()..=Index::zero()) }

    #[inline]
    fn one() -> Self { IndexRange(Index::one()..=Index::one()) }

    #[inline]
    fn largest() -> Self { IndexRange(Index::largest()..=Index::largest()) }

    #[inline]
    fn count(&self) -> usize {
        self.0.end().last_index() as usize - self.0.start().first_index() as usize
    }

    #[inline]
    fn from_index(index: impl Into<u32>) -> Result<Self, bip32::Error> {
        let index = index.into();
        Ok(IndexRange(
            Index::from_index(index)?..=Index::from_index(index)?,
        ))
    }

    #[inline]
    fn first_index(&self) -> u32 { self.0.start().first_index() }

    #[inline]
    fn last_index(&self) -> u32 { self.0.end().last_index() }

    #[inline]
    fn from_derivation_value(value: u32) -> Result<Self, bip32::Error> {
        Ok(IndexRange(
            Index::from_derivation_value(value)?..=Index::from_derivation_value(value)?,
        ))
    }

    #[inline]
    fn first_derivation_value(&self) -> u32 { self.0.start().first_derivation_value() }

    #[inline]
    fn last_derivation_value(&self) -> u32 { self.0.end().last_derivation_value() }

    #[inline]
    fn checked_add_assign(&mut self, _: impl Into<u32>) -> Option<u32> { None }

    #[inline]
    fn checked_sub_assign(&mut self, _: impl Into<u32>) -> Option<u32> { None }

    #[inline]
    fn is_hardened(&self) -> bool { self.0.start().is_hardened() }
}

impl<Index> Display for IndexRange<Index>
where
    Index: SegmentIndexes + Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let inner = self.as_inner();
        if inner.start() == inner.end() {
            write!(f, "{}", inner.start())
        } else {
            write!(f, "{}-{}", inner.start(), inner.end())
        }
    }
}

impl<Index> FromStr for IndexRange<Index>
where
    Index: SegmentIndexes + FromStr,
    bip32::Error: From<<Index as FromStr>::Err>,
{
    type Err = bip32::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split(s);
        Ok(match (split.next(), split.next()) {
            (Some(start), Some(end)) => {
                IndexRange::with(Index::from_str(start)?, Index::from_str(end)?)
            }
            (Some(start), None) => IndexRange::new(Index::from_str(start)?),
            _ => unreachable!(),
        })
    }
}

impl<Index> StrictEncode for IndexRange<Index>
where
    Index: SegmentIndexes + StrictEncode,
{
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
        Ok(strict_encode_list!(e; self.first_index(), self.last_index()))
    }
}

impl<Index> StrictDecode for IndexRange<Index>
where
    Index: SegmentIndexes + StrictDecode,
{
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        Ok(Self::from_inner(RangeInclusive::new(
            Index::strict_decode(&mut d)?,
            Index::strict_decode(&mut d)?,
        )))
    }
}
