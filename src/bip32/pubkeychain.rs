// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use bitcoin::util::bip32::ExtendedPubKey;
use bitcoin::OutPoint;
use miniscript::MiniscriptKey;
use slip132::{Error, FromSlip132};

use crate::bip32::{BranchStep, HardenedIndex, TerminalStep, XpubRef};

#[derive(
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    StrictEncode,
    StrictDecode,
)]
pub struct PubkeyChain {
    pub seed_based: bool,
    pub master: XpubRef,
    pub source_path: Vec<BranchStep>,
    pub branch_index: HardenedIndex,
    pub branch_xpub: ExtendedPubKey,
    pub revocation_seal: Option<OutPoint>,
    pub terminal_path: Vec<TerminalStep>,
}

impl Display for PubkeyChain {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.seed_based {
            f.write_str("!")?;
        }
        if self.master == XpubRef::None && !self.source_path.is_empty() {
            f.write_str("m")?;
        } else {
            Display::fmt(&self.master, f)?;
        }

        f.write_str("/")?;
        f.write_str(
            &self
                .source_path
                .iter()
                .map(BranchStep::to_string)
                .collect::<Vec<_>>()
                .join("/"),
        )?;
        if !self.source_path.is_empty() {
            f.write_str("/")?;
        }
        write!(f, "{}=[{}]", self.branch_index, self.branch_xpub)?;
        if let Some(seal) = self.revocation_seal {
            write!(f, "?{}", seal)?;
        }
        f.write_str("/")?;
        f.write_str(
            &self
                .terminal_path
                .iter()
                .map(TerminalStep::to_string)
                .collect::<Vec<_>>()
                .join("/"),
        )?;

        Ok(())
    }
}

impl FromStr for PubkeyChain {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('/');
        let mut first = split
            .next()
            .expect("split always must return at least one element");

        let seed_based = first.starts_with('!');
        if seed_based {
            first = &first[1..];
        }

        let master = match first {
            "m" => XpubRef::None,
            prefix => XpubRef::from_str(prefix)?,
        };

        let mut split = split.rev();
        let mut terminal_path = Vec::new();
        let (branch_index, branch_xpub, revocation_seal) = loop {
            let step = if let Some(step) = split.next() {
                step
            } else {
                return Err(Error::InvalidDerivationPathFormat);
            };
            if TerminalStep::from_str(step)
                .map(|t| terminal_path.insert(0, t))
                .is_err()
            {
                let mut branch_segment = step.split('?');
                let mut derivation_part = branch_segment
                    .next()
                    .ok_or(Error::InvalidDerivationPathFormat)?
                    .split('=');

                match (
                    derivation_part.next(),
                    derivation_part.next(),
                    derivation_part.next(),
                    branch_segment.next(),
                    branch_segment.next(),
                ) {
                    (Some(index), Some(xpub), None, seal, None) => {
                        let branch_index = HardenedIndex::from_str(index)?;
                        let xpub = &xpub[1..xpub.len() - 1]; // Trimming square brackets
                        let branch_xpub =
                            ExtendedPubKey::from_slip132_str(xpub)?;
                        let revocation_seal = seal
                            .map(|seal| {
                                OutPoint::from_str(seal).map_err(|_| {
                                    Error::InvalidDerivationPathFormat
                                })
                            })
                            .transpose()?;
                        break (branch_index, branch_xpub, revocation_seal);
                    }
                    _ => return Err(Error::InvalidDerivationPathFormat),
                }
            }
        };

        let mut source_path = Vec::new();
        while let Some(step) = split.next() {
            source_path.insert(0, BranchStep::from_str(step)?);
        }

        Ok(PubkeyChain {
            seed_based,
            master,
            source_path,
            branch_index,
            branch_xpub,
            revocation_seal,
            terminal_path,
        })
    }
}

impl MiniscriptKey for PubkeyChain {
    type Hash = Self;

    fn to_pubkeyhash(&self) -> Self::Hash {
        self.clone()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::util::bip32::ExtendedPubKey;

    fn xpubs() -> [ExtendedPubKey; 5] {
        [
            ExtendedPubKey::from_str("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8").unwrap(),
            ExtendedPubKey::from_str("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw").unwrap(),
            ExtendedPubKey::from_str("xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ").unwrap(),
            ExtendedPubKey::from_str("xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5").unwrap(),
            ExtendedPubKey::from_str("xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV").unwrap(),
        ]
    }

    /*
    fn paths() -> [String; 5] {
        [
            format!("m"),
            format!("!m"),
            format!("[{}]"),
            format!("![{}]"),
            format!("m"),
        ]
    }
     */

    #[test]
    fn trivial_paths() {
        let xpubs = xpubs();
        for path in vec![
            format!("m/0'/5'/8'=[{}]/1/0/*", xpubs[0]),
            format!("!m/0'/5'/8'=[{}]/1/0/*", xpubs[1]),
            format!(
                "[{}]/0'/5'/8'=[{}]/1/0/*",
                xpubs[2].identifier(),
                xpubs[3]
            ),
            format!(
                "![{}]/0'/5'/8'=[{}]/1/0/*",
                xpubs[4].identifier(),
                xpubs[1]
            ),
            format!(
                "[{}]/0'/5'/8'=[{}]/1/0/*",
                xpubs[2].fingerprint(),
                xpubs[3]
            ),
            format!(
                "![{}]/0'/5'/8'=[{}]/1/0/*",
                xpubs[4].fingerprint(),
                xpubs[0]
            ),
            format!("[{}]/0'/5'/8'=[{}]/1/0/*", xpubs[2], xpubs[3]),
            format!("![{}]/0'/5'/8'=[{}]/1/0/*", xpubs[4], xpubs[3]),
        ] {
            println!("{}", path);
            assert_eq!(PubkeyChain::from_str(&path).unwrap().to_string(), path);
        }
    }
}
