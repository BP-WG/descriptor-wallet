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

//! Blockchain-specific data types useful for wallets

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use bitcoin::blockdata::constants;
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::{BlockHash, Network, OutPoint, Transaction};
use chrono::NaiveDateTime;
#[cfg(feature = "serde")]
use serde_with::{As, DisplayFromStr};

/// Error parsing string representation of wallet data/structure
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, From,
    Error
)]
#[display(doc_comments)]
#[from(bitcoin::hashes::hex::Error)]
#[from(chrono::ParseError)]
#[from(std::num::ParseIntError)]
#[from(bitcoin::consensus::encode::Error)]
#[from(bitcoin::util::amount::ParseAmountError)]
#[from(bitcoin::blockdata::transaction::ParseOutPointError)]
pub struct ParseError;

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
    StrictDecode
)]
#[display("{block_height}#{block_hash}@{timestamp}")]
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
            block_hash: constants::genesis_block(Network::Bitcoin).block_hash(),
        }
    }
}

impl FromStr for TimeHeight {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut data = s.split(&['#', '@'][..]);
        let me = Self {
            timestamp: data.next().ok_or(ParseError)?.parse()?,
            block_height: data.next().ok_or(ParseError)?.parse()?,
            block_hash: data.next().ok_or(ParseError)?.parse()?,
        };
        if data.next().is_some() {
            Err(ParseError)
        } else {
            Ok(me)
        }
    }
}

#[cfg_attr(
    feature = "serde",
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
    StrictDecode
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
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('@');
        match (split.next(), split.next(), split.next()) {
            (Some(amount), Some(outpoint), None) => Ok(Utxo {
                amount: amount.parse()?,
                outpoint: outpoint.parse()?,
            }),
            _ => Err(ParseError),
        }
    }
}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Getters,
    Clone,
    Eq,
    PartialEq,
    Hash,
    Debug,
    StrictEncode,
    StrictDecode
)]
pub struct MinedTransaction {
    transaction: Transaction,
    #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
    time_height: TimeHeight,
}

impl Display for MinedTransaction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            let tx = bitcoin::consensus::serialize(&self.transaction);
            write!(f, "{}", tx.to_hex())?;
        } else {
            write!(f, "{}", self.transaction.txid())?;
        }
        f.write_str("$")?;
        Display::fmt(&self.time_height, f)
    }
}

impl FromStr for MinedTransaction {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('$');
        match (split.next(), split.next(), split.next()) {
            (Some(tx), Some(th), None) => Ok(MinedTransaction {
                transaction: bitcoin::consensus::deserialize(
                    &Vec::<u8>::from_hex(tx)?,
                )?,
                time_height: th.parse()?,
            }),
            _ => Err(ParseError),
        }
    }
}
