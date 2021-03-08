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
use std::convert::TryFrom;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::ops::RangeInclusive;
use std::str::FromStr;

use amplify::Wrapper;
use bitcoin::util::bip32;
use strict_encoding::{self, StrictDecode, StrictEncode};

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, StrictEncode)]
// Guaranteed to have at least one element
pub struct DerivationRangeVec(Vec<DerivationRange>);

impl DerivationRangeVec {
    pub fn count(&self) -> u32 {
        self.0.iter().map(DerivationRange::count).sum()
    }

    pub fn first_index(&self) -> u32 {
        self.0
            .first()
            .expect("DerivationRangeVec must always have at least one element")
            .first_index()
    }

    pub fn last_index(&self) -> u32 {
        self.0
            .last()
            .expect("DerivationRangeVec must always have at least one element")
            .last_index()
    }
}

impl StrictDecode for DerivationRangeVec {
    fn strict_decode<D: io::Read>(
        d: D,
    ) -> Result<Self, strict_encoding::Error> {
        let vec = Vec::<DerivationRange>::strict_decode(d)?;
        if vec.is_empty() {
            return Err(strict_encoding::Error::DataIntegrityError(s!("DerivationRangeVec when deserialized must has at least one element")));
        }
        Ok(Self(vec))
    }
}

impl From<DerivationRange> for DerivationRangeVec {
    fn from(range: DerivationRange) -> Self {
        Self(vec![range])
    }
}

impl TryFrom<Vec<DerivationRange>> for DerivationRangeVec {
    type Error = bip32::Error;

    fn try_from(value: Vec<DerivationRange>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(bip32::Error::InvalidDerivationPathFormat);
        }
        Ok(Self(value))
    }
}

impl Display for DerivationRangeVec {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(
            &self
                .0
                .iter()
                .map(DerivationRange::to_string)
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

impl FromStr for DerivationRangeVec {
    type Err = bip32::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut vec = Vec::new();
        for item in s.split(',') {
            let mut split = item.split('-');
            let (start, end) = match (split.next(), split.next()) {
                (Some(start), Some(end)) => (
                    start
                        .parse()
                        .map_err(|_| bip32::Error::InvalidChildNumberFormat)?,
                    end.parse()
                        .map_err(|_| bip32::Error::InvalidChildNumberFormat)?,
                ),
                (Some(start), None) => {
                    let idx: u32 = start
                        .parse()
                        .map_err(|_| bip32::Error::InvalidChildNumberFormat)?;
                    (idx, idx)
                }
                _ => unreachable!(),
            };
            let range =
                DerivationRange::from_inner(RangeInclusive::new(start, end));
            vec.push(range);
        }
        Ok(Self(vec))
    }
}

#[derive(Wrapper, Clone, PartialEq, Eq, Hash, Debug, From)]
pub struct DerivationRange(RangeInclusive<u32>);

impl PartialOrd for DerivationRange {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.first_index().partial_cmp(&other.first_index()) {
            Some(Ordering::Equal) => {
                self.last_index().partial_cmp(&other.last_index())
            }
            other => other,
        }
    }
}

impl Ord for DerivationRange {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.first_index().cmp(&other.first_index()) {
            Ordering::Equal => self.last_index().cmp(&other.last_index()),
            other => other,
        }
    }
}

impl DerivationRange {
    pub fn count(&self) -> u32 {
        let inner = self.as_inner();
        inner.end() - inner.start() + 1
    }

    pub fn first_index(&self) -> u32 {
        *self.as_inner().start()
    }

    pub fn last_index(&self) -> u32 {
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
        Ok(strict_encode_list!(e; self.first_index(), self.last_index()))
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
