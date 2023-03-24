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

//! Module implements LNPBP-32 tracking account type

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use bitcoin::secp256k1::{self, Secp256k1, Signing, Verification};
use bitcoin::util::bip32::{
    self, ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey, Fingerprint, KeySource,
};
use bitcoin::{OutPoint, XpubIdentifier};
use slip132::FromSlip132;

use crate::{
    AccountStep, DerivationSubpath, DerivePatternError, HardenedIndex, SegmentIndexes,
    TerminalStep, UnhardenedIndex, XpubRef,
};

/// Errors during tracking acocunt parsing
#[derive(
    Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error, From
)]
#[display(doc_comments)]
pub enum ParseError {
    /// BIP-32 related errors.
    #[display(inner)]
    #[from]
    Bip32(bip32::Error),

    /// SLIP-132 related errors.
    #[display(inner)]
    #[from]
    Slip132(slip132::Error),

    /// unable to parse derivation path `{0}`.
    InvalidDerivationPathFormat(String),

    /// unable to locate account xpub in `{0}`.
    AccountXpubAbsent(String),

    /// incorrect xpub revocation seal `{0}`; the seal must be a valid bitcoin
    /// transaction outpoint in format of `txid:vout`.
    RevocationSeal(String),
}

// TODO: Merge it with the other derivation trait supporting multiple terminal
//       segments
/// Method-trait that can be implemented by all types able to derive a
/// public key with a given path
pub trait DerivePublicKey {
    /// Derives public key for a given unhardened index
    fn derive_public_key<C: Verification>(
        &self,
        ctx: &Secp256k1<C>,
        pat: impl AsRef<[UnhardenedIndex]>,
    ) -> Result<secp256k1::PublicKey, DerivePatternError>;
}

/// HD wallet account guaranteeing key derivation without access to the
/// private keys.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct DerivationAccount {
    /// Reference to the extended master public key, if known
    pub master: XpubRef,

    /// Derivation path for the account, may contain multiple hardened steps
    pub account_path: DerivationSubpath<AccountStep>,

    /// Account-based extended public key at the end of account derivation path
    /// segment
    pub account_xpub: ExtendedPubKey,

    /// Single-use-seal definition for the revocation of account extended public
    /// key
    pub revocation_seal: Option<OutPoint>,

    /// Terminal derivation path, consisting exclusively from unhardened
    /// indexes. This guarantees that the key derivaiton is always possible
    /// without the access to the private key.
    pub terminal_path: DerivationSubpath<TerminalStep>,
}

impl DerivePublicKey for DerivationAccount {
    fn derive_public_key<C: Verification>(
        &self,
        ctx: &Secp256k1<C>,
        pat: impl AsRef<[UnhardenedIndex]>,
    ) -> Result<secp256k1::PublicKey, DerivePatternError> {
        Ok(self
            .account_xpub
            .derive_pub(ctx, &self.to_terminal_derivation_path(pat)?)
            .expect("unhardened derivation failure")
            .public_key)
    }
}

impl DerivationAccount {
    /// Convenience method for deriving tracking account out of extended private
    /// key
    pub fn with<C: Signing>(
        secp: &Secp256k1<C>,
        master_id: XpubIdentifier,
        account_xpriv: ExtendedPrivKey,
        account_path: &[u16],
        terminal_path: impl IntoIterator<Item = TerminalStep>,
    ) -> DerivationAccount {
        let account_xpub = ExtendedPubKey::from_priv(secp, &account_xpriv);
        DerivationAccount {
            master: XpubRef::XpubIdentifier(master_id),
            account_path: account_path
                .iter()
                .copied()
                .map(AccountStep::hardened_index)
                .collect(),
            account_xpub,
            revocation_seal: None,
            terminal_path: terminal_path.into_iter().collect(),
        }
    }

    /// Detects if the tracking account is seed-based
    pub fn seed_based(&self) -> bool { self.master != XpubRef::Unknown }

    /// Counts number of keys which may be derived using this account
    pub fn keyspace_size(&self) -> usize {
        self.terminal_path
            .iter()
            .fold(1usize, |size, step| size * step.count())
    }

    /// Returns fingerprint of the master key, if known
    #[inline]
    pub fn master_fingerprint(&self) -> Option<Fingerprint> { self.master.fingerprint() }

    /// Returns fingerprint of the master key - or, if no master key present, of
    /// the account key
    #[inline]
    pub fn account_fingerprint(&self) -> Fingerprint { self.account_xpub.fingerprint() }

    /// Constructs [`DerivationPath`] for the account extended public key
    #[inline]
    pub fn to_account_derivation_path(&self) -> DerivationPath {
        self.account_path.iter().map(ChildNumber::from).collect()
    }

    /// Returns [`KeySource`] from the extended master public key to the acocunt
    /// key, if known.
    ///
    /// The function can be used for filling in global PSBT public key
    /// information.
    #[inline]
    pub fn account_key_source(&self) -> Option<KeySource> {
        self.master_fingerprint()
            .map(|fp| (fp, self.to_account_derivation_path()))
    }

    /// Constructs [`DerivationPath`] from the extended account key to the final
    /// keys. The path will include only unhardened indexes.
    pub fn to_terminal_derivation_path(
        &self,
        pat: impl AsRef<[UnhardenedIndex]>,
    ) -> Result<DerivationPath, DerivePatternError> {
        let mut iter = pat.as_ref().iter();
        // TODO: Convert into a method on TerminalPath type
        self.terminal_path
            .iter()
            .map(|step| {
                if step.count() == 1 {
                    Ok(ChildNumber::Normal {
                        index: step.first_index(),
                    })
                } else if let Some(index) = iter.next() {
                    if !step.contains(index.first_index()) {
                        Err(DerivePatternError)
                    } else {
                        Ok(ChildNumber::from(*index))
                    }
                } else {
                    Err(DerivePatternError)
                }
            })
            .collect()
    }

    /// Constructs [`DerivationPath`] from the extended master public key to the
    /// final key. This path includes both hardened and unhardened components.
    pub fn to_full_derivation_path(
        &self,
        pat: impl AsRef<[UnhardenedIndex]>,
    ) -> Result<DerivationPath, DerivePatternError> {
        let mut derivation_path =
            Vec::with_capacity(self.account_path.len() + self.terminal_path.len() + 1);
        if self.master.is_some() {
            derivation_path.extend(self.account_path.iter().map(ChildNumber::from));
        }
        derivation_path.extend(&self.to_terminal_derivation_path(pat)?);
        Ok(derivation_path.into())
    }

    /// Extracts BIP32 derivation information for a specific public key derived
    /// at some terminal derivation path.
    ///
    /// This function may be used to construct per-input or per-output
    /// information for PSBT.
    pub fn bip32_derivation<C: Verification>(
        &self,
        ctx: &Secp256k1<C>,
        pat: impl AsRef<[UnhardenedIndex]>,
    ) -> Result<(secp256k1::PublicKey, KeySource), DerivePatternError> {
        Ok((
            self.derive_public_key(ctx, &pat)?,
            (
                self.master_fingerprint()
                    .unwrap_or_else(|| self.account_fingerprint()),
                self.to_full_derivation_path(pat)?,
            ),
        ))
    }
}

impl DerivationAccount {
    fn fmt_account_path(&self, f: &mut Formatter<'_>) -> fmt::Result {
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
        )
    }

    fn fmt_terminal_path(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if !self.terminal_path.is_empty() {
            f.write_str("/")?;
        }
        f.write_str(
            &self
                .terminal_path
                .iter()
                .map(TerminalStep::to_string)
                .collect::<Vec<_>>()
                .join("/"),
        )
    }

    /// Format in Bitcoin core representation:
    /// `[fp/hardened_path/account]xpub/unhardened_path`
    fn fmt_bitcoin_core(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(fp) = self.master.fingerprint() {
            write!(f, "[{:08x}", fp)?;
        } else if !self.account_path.is_empty() {
            f.write_str("[")?;
        }
        self.fmt_account_path(f)?;
        if !self.account_path.is_empty() || self.master.fingerprint().is_some() {
            f.write_str("]")?;
        }
        write!(f, "{}", self.account_xpub)?;
        self.fmt_terminal_path(f)
    }

    /// Format in LNPBP standard representation:
    /// `m=[fp]/hardened_path/account=[xpub]/unhardened_path`
    fn fmt_lnpbp(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.seed_based() {
            f.write_str("m=")?;
            if !self.account_path.is_empty() {
                write!(f, "{}", self.master)?;
            }
        }

        self.fmt_account_path(f)?;
        if !self.account_path.is_empty() {
            f.write_str("=")?;
        }
        write!(f, "[{}]", self.account_xpub)?;
        if let Some(seal) = self.revocation_seal {
            write!(f, "?{}", seal)?;
        }
        self.fmt_terminal_path(f)
    }

    /// Parse from Bitcoin core representation:
    /// `[fp/hardened_path/account]xpub/unhardened_path`
    pub fn from_str_bitcoin_core(s: &str) -> Result<DerivationAccount, ParseError> {
        let mut split = s.split('/');
        let mut account = DerivationAccount {
            master: XpubRef::Unknown,
            account_path: empty!(),
            account_xpub: "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ\
            29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
                .parse()
                .expect("hardcoded dumb xpub"),
            revocation_seal: None,
            terminal_path: empty!(),
        };
        let mut xpub = None;
        if let Some(first) = split.next() {
            if first.starts_with('[') {
                account.master = XpubRef::from_str(first.trim_start_matches('['))?;
                for next in split.by_ref() {
                    if let Some((index, xpub_str)) = next.split_once(']') {
                        account.account_path.push(AccountStep::from_str(index)?);
                        xpub = Some(ExtendedPubKey::from_str(xpub_str)?);
                        break;
                    }
                    account.account_path.push(AccountStep::from_str(next)?);
                }
            } else {
                xpub = Some(ExtendedPubKey::from_str(first)?);
            }
        }

        if let Some(xpub) = xpub {
            account.account_xpub = xpub;
        } else {
            return Err(ParseError::AccountXpubAbsent(s.to_owned()));
        }

        for next in split {
            account.terminal_path.push(TerminalStep::from_str(next)?);
        }

        Ok(account)
    }

    /// Parse from LNPBP standard representation:
    /// `m=[fp]/hardened_path/account=[xpub]/unhardened_path`
    pub fn from_str_lnpbp(s: &str) -> Result<DerivationAccount, ParseError> {
        let mut split = s.split('/');
        let mut first = split
            .next()
            .expect("split always must return at least one element");

        let removed = first.strip_prefix("m=");
        let seed_based = removed.is_some();
        first = removed.unwrap_or(first);

        let master = if !seed_based {
            XpubRef::Unknown
        } else {
            XpubRef::from_str(first)?
        };

        let mut source_path = DerivationSubpath::new();
        if !seed_based && !first.is_empty() {
            source_path.push(AccountStep::from_str(first)?);
        }

        let mut split = split.rev();
        let mut terminal_path = DerivationSubpath::new();
        let (branch_index, branch_xpub, revocation_seal) = loop {
            let step = if let Some(step) = split.next() {
                step
            } else if let XpubRef::Xpub(branch_xpub) = master {
                break (None, branch_xpub, None);
            } else {
                return Err(ParseError::InvalidDerivationPathFormat(s.to_owned()));
            };
            if TerminalStep::from_str(step)
                .map(|t| terminal_path.insert(0, t))
                .is_err()
            {
                let mut branch_segment = step.split('?');
                let mut derivation_part = branch_segment
                    .next()
                    .expect("split always has at least one item")
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
                                    .map_err(|_| ParseError::RevocationSeal(seal.to_owned()))
                            })
                            .transpose()?;
                        break (branch_index, branch_xpub, revocation_seal);
                    }
                    _ => return Err(ParseError::InvalidDerivationPathFormat(s.to_owned())),
                }
            }
        };

        for step in split.rev() {
            source_path.push(AccountStep::from_str(step)?);
        }
        if let Some(branch_index) = branch_index {
            source_path.push(AccountStep::from(branch_index));
        }

        Ok(DerivationAccount {
            master,
            account_path: source_path,
            account_xpub: branch_xpub,
            revocation_seal,
            terminal_path,
        })
    }
}

impl Display for DerivationAccount {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            self.fmt_bitcoin_core(f)
        } else {
            self.fmt_lnpbp(f)
        }
    }
}

impl FromStr for DerivationAccount {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DerivationAccount::from_str_lnpbp(s)
            .or_else(|err| DerivationAccount::from_str_bitcoin_core(s).map_err(|_| err))
    }
}

#[cfg(feature = "miniscript")]
impl miniscript::MiniscriptKey for DerivationAccount {
    type Sha256 = Self;
    type Hash256 = Self;
    type Ripemd160 = Self;
    type Hash160 = Self;
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
    fn trivial_paths_lnpbp() {
        let xpubs = xpubs();
        for path in vec![
            s!("m=[tpubD8P81yEGkUEs1Hk3kdpSuwLBFZYwMCaVBLckeWVneqkJPivLe6uHAmtXt9RGUSRh5EqMecxinhAybyvgBzwKX3sLGGsuuJgnfzQ47arxTCp]/0/*"),
            format!("/0h/5h/8h=[{}]/1/0/*", xpubs[0]),
            format!(
                "/7h=[{}]/0h/5h/8h=[{}]/1/0/*",
                xpubs[2].identifier(),
                xpubs[3]
            ),
            format!(
                "m=[{}]/0h/5h/8h=[{}]/1/*/*",
                xpubs[4].identifier(),
                xpubs[1]
            ),
            format!(
                "/6h=[{}]/0h/5h/8h=[{}]/1/{{0,1}}/*",
                xpubs[2].fingerprint(),
                xpubs[3]
            ),
            format!(
                "m=[{}]/0h/5h/8h=[{}]/1/0/*",
                xpubs[4].fingerprint(),
                xpubs[0]
            ),
            format!(
                "m=[{}]/0/*",
                xpubs[0]
            ),
            format!(
                "/9h=[{}]/0/*",
                xpubs[1]
            ),
            format!("/1h=[{}]/0h/5h/8h=[{}]/1/0/*", xpubs[2], xpubs[3]),
            format!("m=[{}]/0h/5h/8h=[{}]/1/0/*", xpubs[4], xpubs[3]),
        ] {
            assert_eq!(DerivationAccount::from_str_lnpbp(&path).unwrap().to_string(), path);
        }
    }

    #[test]
    fn trivial_paths_bitcoincore() {
        let xpubs = xpubs();
        for path in vec![
            s!("[00000000/48h/0h/0h/2h]xpub69PnGxAGwEBNtGPnxd71p2QbHRZvjDG1BEza1sZdRbd7uWkjHqfGxMburhdEocC5ud2NpkbhwnM29c2zdqWS36wJue1BuJgMnLTpxpxzJe1/{0,1}/*"),
            s!("tpubD8P81yEGkUEs1Hk3kdpSuwLBFZYwMCaVBLckeWVneqkJPivLe6uHAmtXt9RGUSRh5EqMecxinhAybyvgBzwKX3sLGGsuuJgnfzQ47arxTCp/0/*"),
            format!("[/0h/5h/8h]{}/1/0/*", xpubs[0]),
            format!(
                "[{}/0h/5h/8h]{}/1/0/*",
                xpubs[2].fingerprint(),
                xpubs[3]
            ),
            format!(
                "{}/0/*/*",
                xpubs[0]
            ),
        ] {
            let account = DerivationAccount::from_str_bitcoin_core(&path).unwrap();
            assert_eq!(format!("{:#}", account), path);
        }
    }
}
