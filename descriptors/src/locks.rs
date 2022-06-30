// Descriptor wallet library extending bitcoin & miniscript functionality
// by LNP/BP Association (https://lnp-bp.org)
// Written in 2020-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
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

use chrono::Utc;

// TODO: Migrate to rust-bitcoin library

pub const SEQ_NO_MAX_VALUE: u32 = 0xFFFFFFFF;
pub const SEQ_NO_SUBMAX_VALUE: u32 = 0xFFFFFFFE;
pub const SEQ_NO_CSV_DISABLE_MASK: u32 = 0x80000000;
pub const SEQ_NO_CSV_TYPE_MASK: u32 = 0x00400000;
pub const LOCKTIME_THRESHOLD: u32 = 500000000;

/// Time lock interval describing both relative (OP_CHECKSEQUENCEVERIFY) and
/// absolute (OP_CHECKTIMELOCKVERIFY) timelocks.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
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
    NoRand,
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

impl From<SeqNo> for u32 {
    fn from(seqno: SeqNo) -> Self { seqno.into_consensus() }
}

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
    /// Creates `nSeq` value which is not encumbered by either RBF not relative
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

    /// Creates `nSeq` in replace-by-fee mode with the specified order number.
    #[inline]
    pub fn from_rbf(order: u16) -> SeqNo { SeqNo(order as u32 | SEQ_NO_CSV_DISABLE_MASK) }

    /// Creates `nSeq` in replace-by-fee mode with value 0xFFFFFFFD.
    ///
    /// This value is the value supported by the BitBox software.
    #[inline]
    pub fn rbf() -> SeqNo { SeqNo(SEQ_NO_SUBMAX_VALUE - 1) }

    /// Creates relative time lock measured in number of blocks (implies RBF).
    #[inline]
    pub fn from_height(blocks: u16) -> SeqNo { SeqNo(blocks as u32) }

    /// Creates relative time lock measured in number of 512-second intervals
    /// (implies RBF).
    #[inline]
    pub fn from_intervals(intervals: u16) -> SeqNo {
        SeqNo(intervals as u32 | SEQ_NO_CSV_TYPE_MASK)
    }

    /// Creates time lock basing on bitcoin consensus 32-bit value.
    #[inline]
    pub fn from_consensus(consensus: u32) -> SeqNo { SeqNo(consensus) }

    /// Classifies type of `nSeq` value (see [`SeqNoClass`]).
    #[inline]
    pub fn classify(self) -> SeqNoClass {
        match self.0 {
            SEQ_NO_MAX_VALUE | SEQ_NO_SUBMAX_VALUE => SeqNoClass::Unencumbered,
            no if no & SEQ_NO_CSV_DISABLE_MASK != 0 => SeqNoClass::RbfOnly,
            no if no & SEQ_NO_CSV_TYPE_MASK != 0 => SeqNoClass::RelativeTime,
            _ => SeqNoClass::RelativeHeight,
        }
    }

    /// Checks if `nSeq` value opts-in for replace-by-fee (also always true for
    /// relative time locks).
    #[inline]
    pub fn is_rbf(self) -> bool { self.0 < SEQ_NO_SUBMAX_VALUE }

    /// Checks if `nSeq` value opts-in for relative time locks (also always
    /// imply RBG opt-in).
    #[inline]
    pub fn is_timelock(self) -> bool { self.0 & SEQ_NO_CSV_DISABLE_MASK > 1 }

    /// Gets full u32 representation of `nSeq` value as it is serialized in
    /// bitcoin transaction.
    #[inline]
    pub fn into_consensus(self) -> u32 { self.0 }

    /// Gets structured relative time lock information from the `nSeq` value.
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
                Display::fmt(&(self.0 ^ SEQ_NO_CSV_DISABLE_MASK), f)?;
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
                Ok(SeqNo::rbf())
            }
            #[cfg(not(feature = "rand"))]
            {
                Err(ParseError::NoRand)
            }
        } else if s.starts_with("rbf(") && s.ends_with(')') {
            let no = s[4..].trim_end_matches(')').parse()?;
            Ok(SeqNo::from_rbf(no))
        } else if s.starts_with("time(") && s.ends_with(')') {
            let no = s[5..].trim_end_matches(')').parse()?;
            Ok(SeqNo::from_intervals(no))
        } else if s.starts_with("height(") && s.ends_with(')') {
            let no = s[7..].trim_end_matches(')').parse()?;
            Ok(SeqNo::from_height(no))
        } else {
            let no = s.parse()?;
            Ok(SeqNo(no))
        }
    }
}

/// Error constructing timelock from the provided value.
#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error
)]
#[display("invalid timelock value")]
pub struct InvalidTimelock;

/// Value for a transaction `nTimeLock` field which is guaranteed to represent a
/// UNIX timestamp which is always either 0 or a greater than or equal to
/// 500000000.
#[derive(Copy, Clone, PartialOrd, Ord, Eq, PartialEq, Hash, Debug, Default)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct LockTimestamp(u32);

impl From<LockTimestamp> for u32 {
    fn from(lock_timestamp: LockTimestamp) -> Self { lock_timestamp.into_consensus() }
}

impl TryFrom<u32> for LockTimestamp {
    type Error = InvalidTimelock;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        LockTime::from_consensus(value).try_into()
    }
}

impl TryFrom<LockTime> for LockTimestamp {
    type Error = InvalidTimelock;

    fn try_from(lock_time: LockTime) -> Result<Self, Self::Error> {
        if !lock_time.is_time_based() {
            return Err(InvalidTimelock);
        }
        Ok(Self(lock_time.into_consensus()))
    }
}

impl LockTimestamp {
    /// Create zero time lock
    #[inline]
    pub fn anytime() -> Self { Self(0) }

    /// Creates absolute time lock valid since the current timestamp.
    pub fn since_now() -> Self {
        let now = Utc::now();
        LockTimestamp::from_unix_timestamp(now.timestamp() as u32)
            .expect("we are too far in the future")
    }

    /// Creates absolute time lock with the given UNIX timestamp value.
    ///
    /// Timestamp value must be greater or equal to `0x1DCD6500`, otherwise
    /// `None` is returned.
    #[inline]
    pub fn from_unix_timestamp(timestamp: u32) -> Option<Self> {
        if timestamp < LOCKTIME_THRESHOLD {
            None
        } else {
            Some(Self(timestamp))
        }
    }

    /// Converts into full u32 representation of `nSeq` value as it is
    /// serialized in bitcoin transaction.
    #[inline]
    pub fn into_consensus(self) -> u32 { self.0 }

    /// Converts into [`LockTime`] representation.
    #[inline]
    pub fn into_locktime(self) -> LockTime { self.into() }
}

impl Display for LockTimestamp {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("time(")?;
        Display::fmt(&self.0, f)?;
        f.write_str(")")
    }
}

impl FromStr for LockTimestamp {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_lowercase();
        if s == "0" || s == "none" {
            Ok(LockTimestamp::anytime())
        } else if s.starts_with("time(") && s.ends_with(')') {
            let no = s[5..].trim_end_matches(')').parse()?;
            LockTimestamp::try_from(no).map_err(|_| ParseError::InvalidTimestamp(no))
        } else {
            Err(ParseError::InvalidDescriptor(s))
        }
    }
}

/// Value for a transaction `nTimeLock` field which is guaranteed to represent a
/// block height number which is always less than 500000000.
#[derive(Copy, Clone, PartialOrd, Ord, Eq, PartialEq, Hash, Debug, Default)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct LockHeight(u32);

impl From<LockHeight> for u32 {
    fn from(lock_height: LockHeight) -> Self { lock_height.into_consensus() }
}

impl TryFrom<u32> for LockHeight {
    type Error = InvalidTimelock;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        LockTime::from_consensus(value).try_into()
    }
}

impl TryFrom<LockTime> for LockHeight {
    type Error = InvalidTimelock;

    fn try_from(lock_time: LockTime) -> Result<Self, Self::Error> {
        if !lock_time.is_height_based() {
            return Err(InvalidTimelock);
        }
        Ok(Self(lock_time.into_consensus()))
    }
}

impl LockHeight {
    /// Create zero time lock
    #[inline]
    pub fn anytime() -> Self { Self(0) }

    /// Creates absolute time lock with the given block height.
    ///
    /// Block height must be strictly less than `0x1DCD6500`, otherwise
    /// `None` is returned.
    #[inline]
    pub fn from_height(height: u32) -> Option<Self> {
        if height < LOCKTIME_THRESHOLD {
            Some(Self(height))
        } else {
            None
        }
    }

    /// Converts into full u32 representation of `nSeq` value as it is
    /// serialized in bitcoin transaction.
    #[inline]
    pub fn into_consensus(self) -> u32 { self.0 }

    /// Converts into [`LockTime`] representation.
    #[inline]
    pub fn into_locktime(self) -> LockTime { self.into() }
}

impl Display for LockHeight {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("height(")?;
        Display::fmt(&self.0, f)?;
        f.write_str(")")
    }
}

impl FromStr for LockHeight {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_lowercase();
        if s == "0" || s == "none" {
            Ok(LockHeight::anytime())
        } else if s.starts_with("height(") && s.ends_with(')') {
            let no = s[7..].trim_end_matches(')').parse()?;
            LockHeight::try_from(no).map_err(|_| ParseError::InvalidHeight(no))
        } else {
            Err(ParseError::InvalidDescriptor(s))
        }
    }
}

/// Value for a transaction `nTimeLock` field, which can be either a timestamp
/// (>=500000000) or a block height (<500000000). See alse [`LockTimestamp`] and
/// [`LockHeight`] types.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, From, Default)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct LockTime(
    #[from]
    #[from(LockTimestamp)]
    #[from(LockHeight)]
    u32,
);

impl PartialOrd for LockTime {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.is_height_based() != other.is_height_based() {
            None
        } else {
            Some(self.0.cmp(&other.0))
        }
    }
}

impl From<LockTime> for u32 {
    fn from(lock_time: LockTime) -> Self { lock_time.into_consensus() }
}

impl LockTime {
    /// Create zero time lock
    #[inline]
    pub fn anytime() -> Self { Self(0) }

    /// Creates absolute time lock valid since the current timestamp.
    pub fn since_now() -> Self {
        let now = Utc::now();
        LockTime::from_unix_timestamp(now.timestamp() as u32).expect("we are too far in the future")
    }

    /// Creates absolute time lock with the given block height.
    ///
    /// Block height must be strictly less than `0x1DCD6500`, otherwise
    /// `None` is returned.
    #[inline]
    pub fn from_height(height: u32) -> Option<Self> {
        if height < LOCKTIME_THRESHOLD {
            Some(Self(height))
        } else {
            None
        }
    }

    /// Creates absolute time lock with the given UNIX timestamp value.
    ///
    /// Timestamp value must be greater or equal to `0x1DCD6500`, otherwise
    /// `None` is returned.
    #[inline]
    pub fn from_unix_timestamp(timestamp: u32) -> Option<Self> {
        if timestamp < LOCKTIME_THRESHOLD {
            None
        } else {
            Some(Self(timestamp))
        }
    }

    /// Constructs timelock from a bitcoin consensus 32-bit timelock value.
    pub fn from_consensus(value: u32) -> Self { Self(value) }

    /// Checks if the absolute timelock provided by the `nLockTime` value
    /// specifies height-based lock
    #[inline]
    pub fn is_height_based(self) -> bool { self.0 < LOCKTIME_THRESHOLD }

    /// Checks if the absolute timelock provided by the `nLockTime` value
    /// specifies time-based lock
    #[inline]
    pub fn is_time_based(self) -> bool { !self.is_height_based() }

    /// Converts into full u32 representation of `nSeq` value as it is
    /// serialized in bitcoin transaction.
    #[inline]
    pub fn into_consensus(self) -> u32 { self.0 }
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
            Ok(LockTime::anytime())
        } else if s.starts_with("height(") && s.ends_with(')') {
            let no = s[7..].trim_end_matches(')').parse()?;
            LockTime::from_height(no).ok_or(ParseError::InvalidHeight(no))
        } else if s.starts_with("time(") && s.ends_with(')') {
            let no = s[5..].trim_end_matches(')').parse()?;
            LockTime::from_height(no).ok_or(ParseError::InvalidTimestamp(no))
        } else {
            Err(ParseError::InvalidDescriptor(s))
        }
    }
}
