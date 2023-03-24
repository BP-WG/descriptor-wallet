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

use core::fmt::{self, Display, Formatter};
use core::str::FromStr;

use bitcoin::blockdata::transaction::ParseOutPointError;
use bitcoin::hashes::sha256;
use bitcoin::util::bip32;
use bitcoin::util::bip32::Fingerprint;
use bitcoin::{EcdsaSighashType as SighashType, OutPoint};
use bitcoin_blockchain::locks::{self, SeqNo};
use bitcoin_hd::{DerivationSubpath, UnhardenedIndex};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InputDescriptor {
    pub outpoint: OutPoint,
    pub terminal: DerivationSubpath<UnhardenedIndex>,
    pub seq_no: SeqNo,
    pub tweak: Option<(Fingerprint, sha256::Hash)>,
    pub sighash_type: SighashType,
}

impl Display for InputDescriptor {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.outpoint, f)?;
        f.write_str(" ")?;
        Display::fmt(&self.terminal, f)?;
        if let Some((fingerprint, tweak)) = self.tweak {
            f.write_str(" ")?;
            Display::fmt(&fingerprint, f)?;
            Display::fmt(&tweak, f)?;
        }
        if self.seq_no != SeqNo::unencumbered(true) {
            f.write_str(" ")?;
            Display::fmt(&self.seq_no, f)?;
        }
        if self.sighash_type != SighashType::All {
            f.write_str(" ")?;
            Display::fmt(&self.sighash_type, f)?;
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
#[display(doc_comments)]
pub enum ParseError {
    /// invalid sequence number in input descriptor
    #[from]
    InvalidSeqNo(locks::ParseError),

    /// invalid signature hash type in input descriptor
    InvalidSighash(String),

    /// invalid key derivation in input descriptor
    #[from]
    InvalidDerivation(bip32::Error),

    /// invalid hexadecimal P2C tweak representation in input descriptor
    #[from]
    InvalidTweak(bitcoin::hashes::hex::Error),

    /// invalid input outpoint
    #[from]
    InvalidOutpoint(ParseOutPointError),

    /// invalid tweak descriptor format `{0}`; tweak must consists of account
    /// xpub fingerprint and 256-bit number, separated by `:`
    InvalidTweakFormat(String),

    /// invalid input descriptor: outpoint information is required
    NoOutpoint,

    /// invalid input descriptor: terminal derivation information is required
    NoDerivation,

    /// unrecognized input descriptor fragment `{0}`
    UnrecognizedFragment(String),
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseError::InvalidSeqNo(err) => Some(err),
            ParseError::InvalidSighash(_) => None,
            ParseError::InvalidDerivation(err) => Some(err),
            ParseError::InvalidTweak(err) => Some(err),
            ParseError::InvalidOutpoint(err) => Some(err),
            ParseError::InvalidTweakFormat(_) => None,
            ParseError::NoOutpoint => None,
            ParseError::NoDerivation => None,
            ParseError::UnrecognizedFragment(_) => None,
        }
    }
}

impl FromStr for InputDescriptor {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split_whitespace();
        let outpoint = split.next().ok_or(ParseError::NoOutpoint)?;
        let derivation = split.next().ok_or(ParseError::NoDerivation)?;

        let mut d = InputDescriptor {
            outpoint: outpoint.parse()?,
            terminal: derivation.parse()?,
            seq_no: none!(),
            tweak: None,
            sighash_type: SighashType::All,
        };

        for fragment in split {
            if let Ok(seq_no) = SeqNo::from_str(fragment) {
                d.seq_no = seq_no;
            } else if let Ok(sighash_type) = SighashType::from_str(fragment) {
                d.sighash_type = sighash_type;
            } else if fragment.contains(':') {
                let mut split = fragment.split(':');
                d.tweak = match (split.next(), split.next(), split.next()) {
                    (Some(x), _, _) if x.is_empty() => None,
                    (Some(fingerprint), Some(tweak), None) => {
                        Some((fingerprint.parse()?, tweak.parse()?))
                    }
                    (_, _, _) => return Err(ParseError::InvalidTweakFormat(fragment.to_owned())),
                }
            } else {
                return Err(ParseError::UnrecognizedFragment(fragment.to_owned()));
            }
        }

        Ok(d)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn display_from_str() {
        let input = InputDescriptor {
            outpoint: "9a035b0e6e9d07065a31c49884cb1c2d8953636346e91948df75b20e27f50f24:8"
                .parse()
                .unwrap(),
            terminal: "/1/167".parse().unwrap(),
            seq_no: "rbf(1)".parse().unwrap(),
            tweak: None,
            sighash_type: SighashType::AllPlusAnyoneCanPay,
        };

        assert_eq!(
            input.to_string(),
            "9a035b0e6e9d07065a31c49884cb1c2d8953636346e91948df75b20e27f50f24:8 /1/167 rbf(1) \
             SIGHASH_ALL|SIGHASH_ANYONECANPAY"
        );
        assert_eq!(
            input,
            "9a035b0e6e9d07065a31c49884cb1c2d8953636346e91948df75b20e27f50f24:8 /1/167 rbf(1) \
             SIGHASH_ALL|SIGHASH_ANYONECANPAY"
                .parse()
                .unwrap()
        );
    }
}
