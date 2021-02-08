// Rust language amplification library providing multiple generic trait
// implementations, type wrappers, derive macros and other language enhancements
//
// Written in 2019-2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//     Martin Habovstiak <martin.habovstiak@gmail.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

//! Blockchain-specific data types useful for wallets

use chrono::NaiveDateTime;
use std::str::FromStr;

use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, OutPoint};

/// Error parsing string representation of wallet data/structure
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
    Error,
)]
#[display(doc_comments)]
#[from(bitcoin::hashes::hex::Error)]
#[from(chrono::ParseError)]
#[from(std::num::ParseIntError)]
pub struct FromStrError;

#[derive(
    Getters,
    Clone,
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
#[display("{block_height}:{block_hash}@{timestamp}")]
pub struct TimeHeight {
    timestamp: NaiveDateTime,
    block_height: u32,
    block_hash: BlockHash,
}

impl Default for TimeHeight {
    fn default() -> Self {
        TimeHeight {
            timestamp: NaiveDateTime::from_timestamp(1231006500, 0),
            block_height: 0,
            block_hash: BlockHash::from_inner([
                0x6F, 0xE2, 0x8C, 0x0A, 0xB6, 0xF1, 0xB3, 0x72, 0xC1, 0xA6,
                0xA2, 0x46, 0xAE, 0x63, 0xF7, 0x4F, 0x93, 0x1E, 0x83, 0x65,
                0xE1, 0x5A, 0x08, 0x9C, 0x68, 0xD6, 0x19, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ]),
        }
    }
}

impl FromStr for TimeHeight {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut data = s.split(&[':', '@'][..]);
        let me = Self {
            timestamp: data.next().ok_or(FromStrError)?.parse()?,
            block_height: data.next().ok_or(FromStrError)?.parse()?,
            block_hash: data.next().ok_or(FromStrError)?.parse()?,
        };
        if data.next().is_some() {
            Err(FromStrError)
        } else {
            Ok(me)
        }
    }
}

#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Getters,
    Clone,
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
#[display("{amount}@{outpoint}")]
pub struct Utxo {
    outpoint: OutPoint,
    #[cfg_attr(
        feature = "serde",
        serde(with = "bitcoin::util::amount::serde::as_btc")
    )]
    amount: bitcoin::Amount,
}

impl FromStr for Utxo {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('@');
        match (split.next(), split.next(), split.next()) {
            (Some(amount), Some(outpoint), None) => Ok(Utxo {
                amount: amount.parse().map_err(|_| FromStrError)?,
                outpoint: outpoint.parse().map_err(|_| FromStrError)?,
            }),
            _ => Err(FromStrError),
        }
    }
}
