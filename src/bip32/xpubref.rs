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

use std::str::FromStr;

use bitcoin::util::bip32::{self, ExtendedPubKey, Fingerprint};
use bitcoin::XpubIdentifier;

#[derive(
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    Display,
    From,
    StrictEncode,
    StrictDecode,
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", untagged)
)]
#[display("[{0}]", alt = "[{0:#}]")]
pub enum XpubRef {
    #[display("")]
    None,

    #[from]
    Fingerprint(Fingerprint),

    #[from]
    XpubIdentifier(XpubIdentifier),

    #[from]
    Xpub(ExtendedPubKey),
}

impl XpubRef {
    pub fn is_some(&self) -> bool {
        self != &XpubRef::None
    }

    pub fn fingerprint(&self) -> Option<Fingerprint> {
        match self {
            XpubRef::None => None,
            XpubRef::Fingerprint(fp) => Some(*fp),
            XpubRef::XpubIdentifier(xpubid) => {
                Some(Fingerprint::from(&xpubid[0..4]))
            }
            XpubRef::Xpub(xpub) => Some(xpub.fingerprint()),
        }
    }

    pub fn identifier(&self) -> Option<XpubIdentifier> {
        match self {
            XpubRef::None => None,
            XpubRef::Fingerprint(_) => None,
            XpubRef::XpubIdentifier(xpubid) => Some(*xpubid),
            XpubRef::Xpub(xpub) => Some(xpub.identifier()),
        }
    }

    pub fn xpubkey(&self) -> Option<ExtendedPubKey> {
        match self {
            XpubRef::None => None,
            XpubRef::Fingerprint(_) => None,
            XpubRef::XpubIdentifier(_) => None,
            XpubRef::Xpub(xpub) => Some(xpub.clone()),
        }
    }
}

impl FromStr for XpubRef {
    type Err = bip32::Error;

    fn from_str(mut s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Ok(XpubRef::None);
        }
        if s.chars().nth(0) == Some('=') {
            s = &s[2..s.len() - 1];
        } else {
            s = &s[1..s.len() - 1]
        }
        Ok(Fingerprint::from_str(s)
            .map(XpubRef::from)
            .or_else(|_| XpubIdentifier::from_str(s).map(XpubRef::from))
            .map_err(|_| bip32::Error::InvalidDerivationPathFormat)
            .or_else(|_| ExtendedPubKey::from_str(s).map(XpubRef::from))?)
    }
}
