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

#![allow(clippy::needless_borrow)] // Caused by serde transparent derives

//! Hash-locked contract supporting data structures.

use std::borrow::Borrow;

use amplify::hex::{Error, FromHex};
use amplify::{DumbDefault, Slice32, Wrapper};
use bitcoin::hashes::{sha256, Hash};
#[cfg(feature = "serde")]
use serde_with::{As, DisplayFromStr};

/// HTLC payment hash
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(
    Wrapper, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, From
)]
#[derive(StrictEncode, StrictDecode)]
#[display(LowerHex)]
#[wrapper(FromStr, LowerHex, UpperHex)]
pub struct HashLock(#[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))] Slice32);

impl From<HashPreimage> for HashLock {
    fn from(preimage: HashPreimage) -> Self {
        let hash = sha256::Hash::hash(preimage.as_ref());
        Self::from_inner(Slice32::from_inner(hash.into_inner()))
    }
}

impl FromHex for HashLock {
    fn from_byte_iter<I>(iter: I) -> Result<Self, Error>
    where
        I: Iterator<Item = Result<u8, Error>> + ExactSizeIterator + DoubleEndedIterator,
    {
        Ok(Self(Slice32::from_byte_iter(iter)?))
    }
}

impl AsRef<[u8]> for HashLock {
    fn as_ref(&self) -> &[u8] { &self.0[..] }
}

impl Borrow<[u8]> for HashLock {
    fn borrow(&self) -> &[u8] { &self.0[..] }
}

/// HTLC payment preimage
#[allow(clippy::needless_borrow)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(
    Wrapper, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, From
)]
#[derive(StrictEncode, StrictDecode)]
#[display(LowerHex)]
#[wrapper(FromStr, LowerHex, UpperHex)]
pub struct HashPreimage(
    #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))] Slice32,
);

impl HashPreimage {
    #[cfg(feature = "keygen")]
    pub fn random() -> Self { HashPreimage::from_inner(Slice32::random()) }
}

impl FromHex for HashPreimage {
    fn from_byte_iter<I>(iter: I) -> Result<Self, Error>
    where
        I: Iterator<Item = Result<u8, Error>> + ExactSizeIterator + DoubleEndedIterator,
    {
        Ok(Self(Slice32::from_byte_iter(iter)?))
    }
}

impl DumbDefault for HashPreimage {
    fn dumb_default() -> Self { Self(Default::default()) }
}

impl AsRef<[u8]> for HashPreimage {
    fn as_ref(&self) -> &[u8] { &self.0[..] }
}

impl Borrow<[u8]> for HashPreimage {
    fn borrow(&self) -> &[u8] { &self.0[..] }
}
