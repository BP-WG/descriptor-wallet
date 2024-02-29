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

use std::str::FromStr;

use bitcoin::util::bip32::{self, ExtendedPubKey, Fingerprint};
use bitcoin::XpubIdentifier;

/// A reference to the used extended public key at some level of a derivation
/// path.
#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug, Display, From
)]
#[cfg_attr(feature = "strict_encoding", derive(StrictEncode, StrictDecode))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", untagged)
)]
#[display("[{0}]", alt = "[{0:#}]")]
pub enum XpubRef {
    /// Extended public key reference is not present
    #[display("")]
    #[default]
    Unknown,

    /// Extended public key reference using its [`Fingerprint`]
    #[from]
    Fingerprint(Fingerprint),

    /// Extended public key reference using [`XpubIdentifier`]
    #[from]
    XpubIdentifier(XpubIdentifier),

    /// Extended public key reference using full [`ExtendedPubKey`] data
    #[from]
    Xpub(ExtendedPubKey),
}

impl XpubRef {
    /// Detects if the xpub reference is present
    pub fn is_some(&self) -> bool { self != &XpubRef::Unknown }

    /// Returns fingerprint of the extended public key, if the reference is
    /// present
    pub fn fingerprint(&self) -> Option<Fingerprint> {
        match self {
            XpubRef::Unknown => None,
            XpubRef::Fingerprint(fp) => Some(*fp),
            XpubRef::XpubIdentifier(xpubid) => Some(Fingerprint::from(&xpubid[0..4])),
            XpubRef::Xpub(xpub) => Some(xpub.fingerprint()),
        }
    }

    /// Returns [`XpubIdentifier`] of the extended public key, if the reference
    /// is present and has the form of identifier or full extended public key.
    pub fn identifier(&self) -> Option<XpubIdentifier> {
        match self {
            XpubRef::Unknown => None,
            XpubRef::Fingerprint(_) => None,
            XpubRef::XpubIdentifier(xpubid) => Some(*xpubid),
            XpubRef::Xpub(xpub) => Some(xpub.identifier()),
        }
    }

    /// Returns [`ExtendedPubKey`] of the extended public key, if the reference
    /// is present and has the form of full extended public key.
    pub fn xpubkey(&self) -> Option<ExtendedPubKey> {
        match self {
            XpubRef::Unknown => None,
            XpubRef::Fingerprint(_) => None,
            XpubRef::XpubIdentifier(_) => None,
            XpubRef::Xpub(xpub) => Some(*xpub),
        }
    }
}

impl FromStr for XpubRef {
    type Err = bip32::Error;

    fn from_str(mut s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Ok(XpubRef::Unknown);
        }
        if s.starts_with("=[") {
            s = &s[2..s.len() - 1];
        } else if s.starts_with('[') {
            s = &s[1..s.len() - 1]
        }
        Fingerprint::from_str(s)
            .map(XpubRef::from)
            .or_else(|_| XpubIdentifier::from_str(s).map(XpubRef::from))
            .map_err(|_| bip32::Error::InvalidDerivationPathFormat)
            .or_else(|_| ExtendedPubKey::from_str(s).map(XpubRef::from))
    }
}
