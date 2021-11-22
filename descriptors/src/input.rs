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

use core::fmt::{self, Display, Formatter};
use core::str::FromStr;

use bitcoin::hashes::sha256;
use bitcoin::util::bip32;
use bitcoin::SigHashType;
use bitcoin_hd::UnhardenedPath;

use crate::locks::{self, SeqNo};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InputDescriptor {
    pub derivation: UnhardenedPath,
    pub seq_no: SeqNo,
    pub tweak: Option<sha256::Hash>,
    pub sighash_type: SigHashType,
}

impl Display for InputDescriptor {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.derivation, f)?;
        if let Some(tweak) = self.tweak {
            f.write_str("+")?;
            Display::fmt(&tweak, f)?;
        }
        if self.seq_no != SeqNo::unencumbered(true) {
            f.write_str("@")?;
            Display::fmt(&self.seq_no, f)?;
        }
        if self.sighash_type != SigHashType::All {
            f.write_str("#")?;
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
    InvalidSigHash(String),

    /// invalid key derivation in input descriptor
    #[from]
    InvalidDerivation(bip32::Error),

    /// invalid hexadecimal P2C tweak representation in input descriptor
    #[from]
    InvalidTweak(bitcoin::hashes::hex::Error),
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseError::InvalidSeqNo(err) => Some(err),
            ParseError::InvalidSigHash(_) => None,
            ParseError::InvalidDerivation(err) => Some(err),
            ParseError::InvalidTweak(err) => Some(err),
        }
    }
}

impl FromStr for InputDescriptor {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let boundary_3 = s.find('#').unwrap_or(s.len());
        let boundary_2 = s.find('@').unwrap_or(boundary_3);
        let boundary_1 = s.find('+').unwrap_or(boundary_2);
        let derivation = &s[..boundary_1];
        let tweak = &s[boundary_1..boundary_2];
        let seq_no = &s[boundary_2..boundary_3];
        let sighash_type = &s[boundary_3..s.len()];

        let tweak = if tweak.is_empty() {
            None
        } else {
            Some(tweak.parse()?)
        };
        let seq_no = if seq_no.is_empty() {
            SeqNo::unencumbered(true)
        } else {
            seq_no.parse()?
        };
        let sighash_type = if sighash_type.is_empty() {
            SigHashType::All
        } else {
            sighash_type
                .parse()
                .map_err(|msg| ParseError::InvalidSigHash(msg))?
        };

        Ok(Self {
            derivation: derivation.parse()?,
            seq_no,
            tweak,
            sighash_type,
        })
    }
}
