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

//! Blockchain-specific data types useful for wallets

use std::fmt::Debug;
use std::hash::Hash;
use std::str::FromStr;

use bitcoin::blockdata::constants;
use bitcoin::{BlockHash, Network, OutPoint};
use chrono::{DateTime, NaiveDateTime};
#[cfg(feature = "electrum")]
use electrum_client::ListUnspentRes;

/// Error parsing string representation of wallet data/structure
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, From, Error
)]
#[display(doc_comments)]
#[from(bitcoin::hashes::hex::Error)]
#[from(chrono::ParseError)]
#[from(std::num::ParseIntError)]
#[from(bitcoin::consensus::encode::Error)]
#[from(bitcoin::util::amount::ParseAmountError)]
#[from(bitcoin::blockdata::transaction::ParseOutPointError)]
pub struct ParseError;

/// Block mining information
#[derive(Getters, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display("{block_height}#{block_hash}@{timestamp}")]
pub struct TimeHeight {
    timestamp: NaiveDateTime,
    block_height: u32,
    block_hash: BlockHash,
}

impl Default for TimeHeight {
    fn default() -> Self {
        TimeHeight {
            timestamp: DateTime::from_timestamp_millis(1231006500)
                .expect("hardcoded value")
                .naive_utc(),
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

/// Information about transaction mining status
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug, Display
)]
pub enum MiningStatus {
    /// Transaction mining status is undefined
    #[default]
    #[display("undefined")]
    Undefined,

    /// Transaction is unknown
    #[display("unknown_tx")]
    UnknownTx,

    /// Transaction is not mined but present in mempool
    #[display("mempool")]
    Mempool,

    /// Transaction is mined onchain at a block with a given height
    #[display(inner)]
    Blockchain(u64),
}

/// Full UTXO information
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(Getters, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display("{amount}@{outpoint}")]
pub struct Utxo {
    /// Status of the transaction containing this UTXO
    mined: MiningStatus,
    /// UTXO outpoint
    outpoint: OutPoint,
    /// Value stored in the UTXO
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
                mined: MiningStatus::Undefined,
                amount: amount.parse()?,
                outpoint: outpoint.parse()?,
            }),
            _ => Err(ParseError),
        }
    }
}

#[cfg(feature = "electrum")]
impl From<ListUnspentRes> for Utxo {
    fn from(res: ListUnspentRes) -> Self {
        Utxo {
            mined: if res.height == 0 {
                MiningStatus::Mempool
            } else {
                MiningStatus::Blockchain(res.height as u64)
            },
            outpoint: OutPoint::new(res.tx_hash, res.tx_pos as u32),
            amount: bitcoin::Amount::from_sat(res.value),
        }
    }
}
