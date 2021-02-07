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

use bitcoin::util::bip32::{Error, ExtendedPubKey};
use bitcoin::OutPoint;
use miniscript::MiniscriptKey;

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
pub struct PubkeyDeriver {
    pub seed_based: bool,
    pub master: XpubRef,
    pub source_path: Vec<BranchStep>,
    pub branch_index: HardenedIndex,
    pub branch_xpub: ExtendedPubKey,
    pub revocation_seal: Option<OutPoint>,
    pub terminal_path: Vec<TerminalStep>,
}

impl Display for PubkeyDeriver {
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

impl FromStr for PubkeyDeriver {
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
                .map(|t| terminal_path.push(t))
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
                        let branch_xpub = ExtendedPubKey::from_str(xpub)?;
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
            source_path.push(BranchStep::from_str(step)?);
        }

        Ok(PubkeyDeriver {
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

impl MiniscriptKey for PubkeyDeriver {
    type Hash = Self;

    fn to_pubkeyhash(&self) -> Self::Hash {
        self.clone()
    }
}
