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
use std::iter::FromIterator;
use std::str::FromStr;

use bitcoin::secp256k1::{Secp256k1, Verification};
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPubKey};
use miniscript::MiniscriptKey;
use regex::Regex;
use slip132::FromSlip132;
use strict_encoding::{self, StrictDecode, StrictEncode};

use super::{DerivationRangeVec, HardenedNormalSplit, UnhardenedIndex};

#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    StrictEncode,
    StrictDecode
)]
// [master_xpub]/branch_path=[branch_xpub]/terminal_path/index_ranges
pub struct DerivationComponents {
    pub master_xpub: ExtendedPubKey,
    pub branch_path: DerivationPath,
    pub branch_xpub: ExtendedPubKey,
    pub terminal_path: Vec<u32>,
    pub index_ranges: Option<DerivationRangeVec>,
}

impl DerivationComponents {
    pub fn count(&self) -> u32 {
        match self.index_ranges {
            None => ::std::u32::MAX,
            Some(ref ranges) => ranges.count(),
        }
    }

    pub fn derivation_path(&self) -> DerivationPath {
        self.branch_path.extend(self.terminal_path())
    }

    pub fn terminal_path(&self) -> DerivationPath {
        DerivationPath::from_iter(
            self.terminal_path
                .iter()
                .map(|i| ChildNumber::Normal { index: *i }),
        )
    }

    pub fn index_ranges_string(&self) -> String {
        self.index_ranges
            .as_ref()
            .map(DerivationRangeVec::to_string)
            .unwrap_or_default()
    }

    pub fn child<C: Verification>(
        &self,
        ctx: &Secp256k1<C>,
        child: u32,
    ) -> ExtendedPubKey {
        let derivation = self
            .terminal_path()
            .into_child(ChildNumber::Normal { index: child });
        self.branch_xpub
            .derive_pub(ctx, &derivation)
            .expect("Non-hardened derivation does not fail")
    }

    pub fn derive_public_key<C: Verification>(
        &self,
        ctx: &Secp256k1<C>,
        child_index: UnhardenedIndex,
    ) -> bitcoin::PublicKey {
        self.child(ctx, child_index.into()).public_key
    }
}

impl Display for DerivationComponents {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "[{}]", self.master_xpub.fingerprint())?;
        } else {
            write!(f, "[{}]", self.master_xpub)?;
        }
        f.write_str(self.branch_path.to_string().trim_start_matches("m"))?;
        if f.alternate() {
            f.write_str("/")?;
        } else if self.branch_xpub != self.master_xpub {
            write!(f, "=[{}]", self.branch_xpub)?;
        }
        f.write_str(self.terminal_path().to_string().trim_start_matches("m"))?;
        f.write_str("/")?;
        if let Some(_) = self.index_ranges {
            f.write_str(&self.index_ranges_string())
        } else {
            f.write_str("*")
        }
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(inner)]
pub struct ComponentsParseError(pub String);

impl FromStr for DerivationComponents {
    type Err = ComponentsParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
            static ref RE_DERIVATION: Regex = Regex::new(
                r"(?x)^
                \[(?P<xpub>[xyztuvXYZTUV]pub[1-9A-HJ-NP-Za-km-z]{107,108})\]
                /(?P<deriv>([0-9]{1,10}[h']?)+)
                (/(?P<range>\*|([0-9]{1,10}([,-][0-9]{1,10})*)))?
                $",
            )
            .expect("Regexp expression for `DerivationComponents` is broken");
        }

        let mut split = s.split('=');
        let (branch, terminal) =
            match (split.next(), split.next(), split.next()) {
                (Some(branch), Some(terminal), None) => {
                    (Some(branch), terminal)
                }
                (Some(terminal), None, None) => (None, terminal),
                (None, None, None) => unreachable!(),
                _ => Err(ComponentsParseError(s!("Derivation components \
                                                  string must contain at \
                                                  most two parts \
                                                  separated by `=`")))?,
            };

        let caps = if let Some(caps) = RE_DERIVATION.captures(terminal) {
            caps
        } else {
            Err(ComponentsParseError(s!(
                "Wrong composition of derivation components data"
            )))?
        };

        let branch_xpub = ExtendedPubKey::from_slip132_str(
            caps.name("xpub").expect("regexp engine is broken").as_str(),
        )
        .map_err(|err| ComponentsParseError(err.to_string()))?;
        let terminal_path = caps
            .name("deriv")
            .expect("regexp engine is broken")
            .as_str();
        let terminal_path =
            DerivationPath::from_str(&format!("m/{}", terminal_path))
                .map_err(|err| ComponentsParseError(err.to_string()))?;
        let (prefix, terminal_path) = terminal_path.hardened_normal_split();
        if !prefix.as_ref().is_empty() {
            Err(ComponentsParseError(s!(
                "Terminal derivation path must not contain hardened keys"
            )))?;
        }
        let index_ranges = caps
            .name("range")
            .as_ref()
            .map(regex::Match::as_str)
            .map(DerivationRangeVec::from_str)
            .transpose()
            .map_err(|err| ComponentsParseError(err.to_string()))?;

        let (master_xpub, branch_path) = if let Some(caps) =
            branch.and_then(|branch| RE_DERIVATION.captures(branch))
        {
            let master_xpub = ExtendedPubKey::from_slip132_str(
                caps.name("xpub").expect("regexp engine is broken").as_str(),
            )
            .map_err(|err| ComponentsParseError(err.to_string()))?;
            let branch_path = caps
                .name("deriv")
                .expect("regexp engine is broken")
                .as_str();
            let branch_path =
                DerivationPath::from_str(&format!("m/{}", branch_path))
                    .map_err(|err| ComponentsParseError(err.to_string()))?;
            (master_xpub, branch_path)
        } else {
            (
                branch_xpub.clone(),
                DerivationPath::from(Vec::<ChildNumber>::new()),
            )
        };

        Ok(DerivationComponents {
            master_xpub,
            branch_path,
            branch_xpub,
            terminal_path,
            index_ranges,
        })
    }
}

impl MiniscriptKey for DerivationComponents {
    type Hash = Self;

    fn to_pubkeyhash(&self) -> Self::Hash { self.clone() }
}
