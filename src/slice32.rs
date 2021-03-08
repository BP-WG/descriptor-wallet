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

use std::fmt::{self, Debug, Formatter, LowerHex, UpperHex};
use std::io;
use std::str::FromStr;

use amplify::Wrapper;
use bitcoin::hashes::hex::{Error, FromHex, ToHex};
use bitcoin::hashes::{sha256, Hash};
use strict_encoding::{StrictDecode, StrictEncode};

/// Wrapper type for all slice-based 256-bit types implementing many important
/// traits, so types based on it can simply derive their implementations
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Wrapper,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Display,
    Default,
    From,
)]
#[display(LowerHex)]
pub struct Slice32(
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "serde_helpers::to_hex",
            deserialize_with = "serde_helpers::from_hex"
        )
    )]
    [u8; 32],
);

impl Slice32 {
    #[cfg(feature = "keygen")]
    pub fn random() -> Self {
        use bitcoin::secp256k1::rand;

        let mut entropy = [0u8; 32];
        entropy.copy_from_slice(
            &bitcoin::secp256k1::SecretKey::new(&mut rand::thread_rng())[..],
        );
        Slice32::from_inner(entropy)
    }

    pub fn from_slice(slice: impl AsRef<[u8]>) -> Option<Slice32> {
        if slice.as_ref().len() != 32 {
            return None;
        }
        let mut inner = [0u8; 32];
        inner.copy_from_slice(slice.as_ref());
        Some(Self(inner))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl StrictEncode for Slice32 {
    fn strict_encode<E: io::Write>(
        &self,
        e: E,
    ) -> Result<usize, strict_encoding::Error> {
        // We use the same encoding as used by hashes - and ensure this by
        // cross-converting with hash
        sha256::Hash::from_inner(self.to_inner()).strict_encode(e)
    }
}

impl StrictDecode for Slice32 {
    fn strict_decode<D: io::Read>(
        d: D,
    ) -> Result<Self, strict_encoding::Error> {
        let hash = sha256::Hash::strict_decode(d)?;
        Ok(Slice32::from_inner(hash.into_inner()))
    }
}

impl Debug for Slice32 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Slice32({})", self.to_hex())
    }
}

impl FromStr for Slice32 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl FromHex for Slice32 {
    fn from_byte_iter<I>(iter: I) -> Result<Self, Error>
    where
        I: Iterator<Item = Result<u8, Error>>
            + ExactSizeIterator
            + DoubleEndedIterator,
    {
        let vec = Vec::<u8>::from_byte_iter(iter)?;
        if vec.len() != 32 {
            return Err(Error::InvalidLength(32, vec.len()));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&vec);
        Ok(Slice32(id))
    }
}

impl LowerHex for Slice32 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(
                f,
                "{}..{}",
                self.0[..4].to_hex(),
                self.0[(self.0.len() - 4)..].to_hex()
            )
        } else {
            f.write_str(&self.0.to_hex())
        }
    }
}

impl UpperHex for Slice32 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(
                f,
                "{}..{}",
                self.0[..4].to_hex().to_ascii_uppercase(),
                self.0[(self.0.len() - 4)..].to_hex().to_ascii_uppercase()
            )
        } else {
            f.write_str(&self.0.to_hex().to_ascii_uppercase())
        }
    }
}

#[cfg(feature = "serde")]
pub(crate) mod serde_helpers {
    //! Serde serialization helpers

    use bitcoin::hashes::hex::{FromHex, ToHex};
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serializes `buffer` to a lowercase hex string.
    pub fn to_hex<S>(
        buffer: &[u8; 32],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&buffer.as_ref().to_hex())
    }

    /// Deserializes a lowercase hex string to a `Vec<u8>`.
    pub fn from_hex<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        String::deserialize(deserializer).and_then(|string| {
            let vec = Vec::<u8>::from_hex(&string)
                .map_err(|_| D::Error::custom("wrong hex data"))?;
            if vec.len() != 32 {
                Err(D::Error::custom("Wrong 32-byte slice data length"))?
            }
            let mut slice32 = [0u8; 32];
            slice32.copy_from_slice(&vec[0..32]);
            Ok(slice32)
        })
    }
}
