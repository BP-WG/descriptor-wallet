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

//! Relative and absolute time locks on transactions

use core::cmp::Ordering;
use core::fmt::{self, Display, Formatter};
use core::num::ParseIntError;
use core::str::FromStr;

use bitcoin::secp256k1::rand::{thread_rng, Rng};

// TODO: Migrate to rust-bitcoin library

pub const SEQ_NO_MAX_VALUE: u32 = 0xFFFFFFFF;
pub const SEQ_NO_SUBMAX_VALUE: u32 = 0xFFFFFFFE;
pub const SEQ_NO_CSV_DISABLE_MASK: u32 = 0x80000000;
pub const SEQ_NO_CSV_TYPE_MASK: u32 = 0x00400000;
pub const LOCKTIME_THRESHOLD: u32 = 500000000;

/// Time lock interval describing both relative (OP_CHECKSEQUENCEVERIFY) and
/// absolute (OP_CHECKTIMELOCKVERIFY) timelocks.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum TimeLockInterval {
    /// Describes number of blocks for the timelock
    #[display("height({0})")]
    Height(u16),

    /// Describes number of 512-second intervals for the timelock
    #[display("time({0})")]
    Time(u16),
}

/// Classes for `nSeq` values
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum SeqNoClass {
    /// No RBF (opt-out) and timelocks.
    ///
    /// Corresponds to `0xFFFFFFFF` and `0xFFFFFFFE` values
    Unencumbered,

    /// RBF opt-in, but no timelock applied.
    ///
    /// Values from `0x80000000` to `0xFFFFFFFD` inclusively
    RbfOnly,

    /// Both RBF and relative height-based lock is applied.
    RelativeTime,

    /// Both RBF and relative time-based lock is applied.
    RelativeHeight,
}

#[derive(Debug, Clone, PartialEq, Eq, From, Display)]
#[display(doc_comments)]
pub enum ParseError {
    /// invalid number in time lock descriptor
    #[from]
    InvalidNumber(ParseIntError),

    /// block height `{0}` is too large for time lock
    InvalidHeight(u32),

    /// timestamp `{0}` is too small for time lock
    InvalidTimestamp(u32),

    /// time lock descriptor `{0}` is not recognized
    InvalidDescriptor(String),

    /// use of randomly-generated RBF sequence numbers requires compilation
    /// with `rand` feature
    ParseError,
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseError::InvalidNumber(err) => Some(err),
            _ => None,
        }
    }
}

/// Value for `nSeq` field of a transaction output
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, From)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct SeqNo(#[from] u32);

impl Default for SeqNo {
    #[inline]
    fn default() -> Self { SeqNo(SEQ_NO_MAX_VALUE) }
}

impl PartialOrd for SeqNo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.classify() != other.classify() {
            None
        } else {
            Some(self.0.cmp(&other.0))
        }
    }
}

impl SeqNo {
    /// Create `nSeq` value which is not encumbered by either RBF not relative
    /// time locks.
    ///
    /// # Arguments
    /// - `max` defines whether `nSeq` should be set to the `0xFFFFFFFF`
    ///   (`true`) or `0xFFFFFFFe`.
    #[inline]
    pub fn unencumbered(max: bool) -> SeqNo {
        SeqNo(if max {
            SEQ_NO_MAX_VALUE
        } else {
            SEQ_NO_SUBMAX_VALUE
        })
    }

    /// Create `nSeq` in replace-by-fee mode with the specified order number.
    #[inline]
    pub fn with_rbf(order: u16) -> SeqNo {
        SeqNo(order as u32 | SEQ_NO_CSV_DISABLE_MASK)
    }

    /// Create relative time lock measured in number of blocks (implies RBF).
    #[inline]
    pub fn with_height(blocks: u16) -> SeqNo { SeqNo(blocks as u32) }

    /// Create relative time lock measured in number of 512-second intervals
    /// (implies RBF).
    #[inline]
    pub fn with_time(intervals: u16) -> SeqNo {
        SeqNo(intervals as u32 | SEQ_NO_CSV_TYPE_MASK)
    }

    /// Classify type of `nSeq` value (see [`SeqNoClass`]).
    #[inline]
    pub fn classify(self) -> SeqNoClass {
        match self.0 {
            SEQ_NO_MAX_VALUE | SEQ_NO_SUBMAX_VALUE => SeqNoClass::Unencumbered,
            no if no & SEQ_NO_CSV_DISABLE_MASK != 0 => SeqNoClass::RbfOnly,
            no if no & SEQ_NO_CSV_TYPE_MASK != 0 => SeqNoClass::RelativeTime,
            _ => SeqNoClass::RelativeHeight,
        }
    }

    /// Check if `nSeq` value opts-in for replace-by-fee (also always true for
    /// relative time locks).
    #[inline]
    pub fn is_rbf(self) -> bool { self.0 < SEQ_NO_SUBMAX_VALUE }

    /// Check if `nSeq` value opts-in for relative time locks (also always imply
    /// RBG opt-in).
    #[inline]
    pub fn is_timelock(self) -> bool { self.0 & SEQ_NO_CSV_DISABLE_MASK > 1 }

    /// Get full u32 representation of `nSeq` value as it is serialized in
    /// bitcoin transaction.
    #[inline]
    pub fn as_u32(self) -> u32 { self.0 }

    /// Get structured relative time lock information from the `nSeq` value.
    /// See [`TimeLockInterval`].
    pub fn time_lock_interval(self) -> Option<TimeLockInterval> {
        if self.0 & SEQ_NO_CSV_DISABLE_MASK != 0 {
            None
        } else if self.0 & SEQ_NO_CSV_TYPE_MASK != 0 {
            Some(TimeLockInterval::Time((self.0 & 0xFFFF) as u16))
        } else {
            Some(TimeLockInterval::Height((self.0 & 0xFFFF) as u16))
        }
    }
}

impl Display for SeqNo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.classify() {
            SeqNoClass::Unencumbered => Display::fmt(&self.0, f),
            SeqNoClass::RbfOnly => {
                f.write_str("rbf(")?;
                Display::fmt(&self.0, f)?;
                f.write_str(")")
            }
            _ if self.0 >> 16 & 0xFFBF > 0 => Display::fmt(&self.0, f),
            SeqNoClass::RelativeTime => {
                let value = self.0 & 0xFFFF;
                f.write_str("time(")?;
                Display::fmt(&value, f)?;
                f.write_str(")")
            }
            SeqNoClass::RelativeHeight => {
                let value = self.0 & 0xFFFF;
                f.write_str("height(")?;
                Display::fmt(&value, f)?;
                f.write_str(")")
            }
        }
    }
}

impl FromStr for SeqNo {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_lowercase();
        if s == "rbf" {
            #[cfg(feature = "rand")]
            {
                let mut rng = thread_rng();
                let no = rng.gen_range(0, u16::MAX / 2);
                Ok(SeqNo::with_rbf(no))
            }
            #[cfg(not(feature = "rand"))]
            {
                Err(ParseError::NoRand)
            }
        } else if s.starts_with("rbf(") && s.ends_with(")") {
            let no = s[4..].trim_end_matches(')').parse()?;
            Ok(SeqNo::with_rbf(no))
        } else if s.starts_with("time(") && s.ends_with(")") {
            let no = s[5..].trim_end_matches(')').parse()?;
            Ok(SeqNo::with_time(no))
        } else if s.starts_with("height(") && s.ends_with(")") {
            let no = s[7..].trim_end_matches(')').parse()?;
            Ok(SeqNo::with_height(no))
        } else {
            let no = s.parse()?;
            Ok(SeqNo(no))
        }
    }
}

/// Value for a transaction `nTimeLock` field
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, From, Default)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct LockTime(#[from] u32);

impl PartialOrd for LockTime {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.is_height_based() != other.is_height_based() {
            None
        } else {
            Some(self.0.cmp(&other.0))
        }
    }
}

impl LockTime {
    /// Create zero time lock
    #[inline]
    pub fn new() -> Self { Self(0) }

    /// Create absolute time lock with the given block height.
    ///
    /// Block height must be strictly less than `0x1DCD6500`, otherwise
    /// `None` is returned.
    #[inline]
    pub fn with_height(height: u32) -> Option<Self> {
        if height < LOCKTIME_THRESHOLD {
            Some(Self(height))
        } else {
            None
        }
    }

    /// Create absolute time lock with the given UNIX timestamp value.
    ///
    /// Timestamp value must be greater or equal to `0x1DCD6500`, otherwise
    /// `None` is returned.
    #[inline]
    pub fn with_unix_timestamp(timestamp: u32) -> Option<Self> {
        if timestamp < LOCKTIME_THRESHOLD {
            None
        } else {
            Some(Self(timestamp))
        }
    }

    /// Checks if the absolute timelock provided by the `nLockTime` value
    /// specifies height-based lock
    #[inline]
    pub fn is_height_based(self) -> bool { self.0 < LOCKTIME_THRESHOLD }

    /// Checks if the absolute timelock provided by the `nLockTime` value
    /// specifies time-based lock
    #[inline]
    pub fn is_time_based(self) -> bool { !self.is_height_based() }

    /// Get full u32 representation of `nSeq` value as it is serialized in
    /// bitcoin transaction.
    #[inline]
    pub fn as_u32(self) -> u32 { self.0 }
}

impl Display for LockTime {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.is_height_based() {
            f.write_str("height(")?;
            Display::fmt(&self.0, f)?;
            f.write_str(")")
        } else {
            f.write_str("time(")?;
            Display::fmt(&self.0, f)?;
            f.write_str(")")
        }
    }
}

impl FromStr for LockTime {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_lowercase();
        if s == "0" || s == "none" {
            Ok(LockTime::new())
        } else if s.starts_with("height(") && s.ends_with(")") {
            let no = s[7..].trim_end_matches(')').parse()?;
            LockTime::with_height(no).ok_or(ParseError::InvalidHeight(no))
        } else if s.starts_with("time(") && s.ends_with(")") {
            let no = s[5..].trim_end_matches(')').parse()?;
            LockTime::with_height(no).ok_or(ParseError::InvalidTimestamp(no))
        } else {
            Err(ParseError::InvalidDescriptor(s))
        }
    }
}
