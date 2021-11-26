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

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use bitcoin::secp256k1::{self, Secp256k1, Verification};
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPubKey, Fingerprint, KeySource};
use bitcoin::OutPoint;
use miniscript::MiniscriptKey;
use slip132::{Error, FromSlip132};

use crate::{AccountStep, HardenedIndex, SegmentIndexes, TerminalStep, UnhardenedIndex, XpubRef};

/// the provided derive pattern does not match descriptor derivation
/// wildcard
#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error
)]
#[display(doc_comments)]
pub struct DerivePatternError;

#[derive(
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    StrictEncode,
    StrictDecode
)]
pub struct PubkeyChain {
    pub seed_based: bool,
    pub master: XpubRef,
    pub account_path: Vec<AccountStep>,
    pub account_xpub: ExtendedPubKey,
    pub revocation_seal: Option<OutPoint>,
    pub terminal_path: Vec<TerminalStep>,
}

impl PubkeyChain {
    pub fn keyspace_size(&self) -> usize {
        self.terminal_path
            .iter()
            .fold(1usize, |size, step| size * step.count())
    }

    #[inline]
    pub fn master_fingerprint(&self) -> Fingerprint {
        self.master
            .fingerprint()
            .unwrap_or_else(|| self.account_xpub.fingerprint())
    }

    #[inline]
    pub fn account_fingerprint(&self) -> Fingerprint { self.account_xpub.fingerprint() }

    #[inline]
    pub fn account_derivation(&self) -> DerivationPath {
        self.account_path.iter().map(ChildNumber::from).collect()
    }

    #[inline]
    pub fn account_key_source(&self) -> KeySource {
        match self.master {
            XpubRef::Unknown => (self.account_xpub.fingerprint(), none!()),
            _ => (self.master_fingerprint(), self.account_derivation()),
        }
    }

    pub fn terminal_derivation_path(
        &self,
        pat: impl AsRef<[UnhardenedIndex]>,
    ) -> Result<DerivationPath, DerivePatternError> {
        let mut iter = pat.as_ref().iter();
        // TODO: Convert into a method on TerminalPath type
        self.terminal_path
            .iter()
            .map(|step| {
                if step.count() > 1 {
                    Ok(ChildNumber::Normal {
                        index: step.first_index(),
                    })
                } else if let Some(index) = iter.next() {
                    Ok(ChildNumber::from(*index))
                } else {
                    Err(DerivePatternError)
                }
            })
            .collect()
    }

    pub fn derivation_path(
        &self,
        pat: impl AsRef<[UnhardenedIndex]>,
    ) -> Result<DerivationPath, DerivePatternError> {
        let mut derivation_path =
            Vec::with_capacity(self.account_path.len() + self.terminal_path.len() + 1);
        if self.master.is_some() {
            derivation_path.extend(self.account_path.iter().map(ChildNumber::from));
        }
        derivation_path.extend(&self.terminal_derivation_path(pat)?);
        Ok(derivation_path.into())
    }

    pub fn derive_pubkey<C: Verification>(
        &self,
        ctx: &Secp256k1<C>,
        pat: impl AsRef<[UnhardenedIndex]>,
    ) -> Result<secp256k1::PublicKey, DerivePatternError> {
        Ok(self
            .account_xpub
            .derive_pub(ctx, &self.terminal_derivation_path(pat)?)
            .expect("Unhardened derivation failure")
            .public_key)
    }

    pub fn bip32_derivation<C: Verification>(
        &self,
        ctx: &Secp256k1<C>,
        pat: impl AsRef<[UnhardenedIndex]>,
    ) -> Result<(secp256k1::PublicKey, KeySource), DerivePatternError> {
        Ok((
            self.derive_pubkey(ctx, &pat)?,
            (
                self.account_fingerprint(),
                self.terminal_derivation_path(pat)?,
            ),
        ))
    }
}

impl Display for PubkeyChain {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.seed_based {
            f.write_str("m")?;
            if self.master != XpubRef::Unknown {
                f.write_str("=")?;
            }
        }

        Display::fmt(&self.master, f)?;

        if !self.account_path.is_empty() {
            f.write_str("/")?;
        }
        f.write_str(
            &self
                .account_path
                .iter()
                .map(AccountStep::to_string)
                .collect::<Vec<_>>()
                .join("/"),
        )?;
        if !self.account_path.is_empty() || self.seed_based {
            f.write_str("=")?;
        }
        write!(f, "[{}]", self.account_xpub)?;
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

        let removed = first.strip_prefix('m');
        let seed_based = removed.is_some();
        first = removed.unwrap_or(first);
        if seed_based {
            first = first.strip_prefix('=').unwrap_or(first);
        }

        let mut master = if first.is_empty() {
            XpubRef::Unknown
        } else {
            XpubRef::from_str(first)?
        };

        let mut split = split.rev();
        let mut terminal_path = Vec::new();
        let (branch_index, branch_xpub, revocation_seal) = loop {
            let step = if let Some(step) = split.next() {
                step
            } else if let XpubRef::Xpub(branch_xpub) = master {
                master = XpubRef::Unknown;
                break (None, branch_xpub, None);
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
                    (index, Some(xpub), None, seal, None) => {
                        let branch_index = index.map(HardenedIndex::from_str).transpose()?;
                        let xpub = &xpub[1..xpub.len() - 1]; // Trimming square brackets
                        let branch_xpub = ExtendedPubKey::from_slip132_str(xpub)?;
                        let revocation_seal = seal
                            .map(|seal| {
                                OutPoint::from_str(seal)
                                    .map_err(|_| Error::InvalidDerivationPathFormat)
                            })
                            .transpose()?;
                        break (branch_index, branch_xpub, revocation_seal);
                    }
                    _ => return Err(Error::InvalidDerivationPathFormat),
                }
            }
        };

        let mut source_path = vec![];
        if let Some(branch_index) = branch_index {
            source_path.push(AccountStep::from(branch_index));
        }
        for step in split {
            source_path.insert(0, AccountStep::from_str(step)?);
        }

        Ok(PubkeyChain {
            seed_based,
            master,
            account_path: source_path,
            account_xpub: branch_xpub,
            revocation_seal,
            terminal_path,
        })
    }
}

impl MiniscriptKey for PubkeyChain {
    type Hash = Self;

    fn to_pubkeyhash(&self) -> Self::Hash { self.clone() }
}

#[cfg(test)]
mod test {
    use bitcoin::util::bip32::ExtendedPubKey;

    use super::*;

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
            s!("m=[tpubD8P81yEGkUEs1Hk3kdpSuwLBFZYwMCaVBLckeWVneqkJPivLe6uHAmtXt9RGUSRh5EqMecxinhAybyvgBzwKX3sLGGsuuJgnfzQ47arxTCp]/0/*"),
            format!("m/0'/5'/8'=[{}]/1/0/*", xpubs[0]),
            format!(
                "[{}]/0'/5'/8'=[{}]/1/0/*",
                xpubs[2].identifier(),
                xpubs[3]
            ),
            format!(
                "m=[{}]/0'/5'/8'=[{}]/1/0/*",
                xpubs[4].identifier(),
                xpubs[1]
            ),
            format!(
                "[{}]/0'/5'/8'=[{}]/1/0/*",
                xpubs[2].fingerprint(),
                xpubs[3]
            ),
            format!(
                "m=[{}]/0'/5'/8'=[{}]/1/0/*",
                xpubs[4].fingerprint(),
                xpubs[0]
            ),
            format!(
                "m=[{}]/0/*",
                xpubs[0]
            ),
            format!(
                "[{}]/0/*",
                xpubs[1]
            ),
            format!("[{}]/0'/5'/8'=[{}]/1/0/*", xpubs[2], xpubs[3]),
            format!("m=[{}]/0'/5'/8'=[{}]/1/0/*", xpubs[4], xpubs[3]),
        ] {
            assert_eq!(PubkeyChain::from_str(&path).unwrap().to_string(), path);
        }
    }
}
