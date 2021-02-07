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
    serde(crate = "serde_crate", rename_all = "lowercase")
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
