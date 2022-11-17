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

use amplify::hex::{FromHex, ToHex};

use crate::raw::ProprietaryKey;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum ProprietaryKeyError {
    /// incorrect proprietary key location `{0}`; allowed location formats are
    /// `input(X)`, `output(X)` and `global`, where `X` is a 16-bit decimal
    /// integer.
    WrongLocation(String),

    /// incorrect proprietary key type definition `{0}`.
    ///
    /// Type definition must start with a ket prefix in form of a short ASCII
    /// string, followed by a key subtype represented by a 8-bit decimal integer
    /// in parentheses without whitespacing. Example: `DBC(5)`
    WrongType(String),

    /// incorrect proprietary key format `{0}`.
    ///
    /// Proprietary key descriptor must consists of whitespace-separated three
    /// parts:
    /// 1) key location, in form of `input(no)`, `output(no)`, or `global`;
    /// 2) key type, in form of `prefix(no)`;
    /// 3) key-value pair, in form of `key:value`, where both key and value
    ///    must be hexadecimal bytestrings; one of them may be omitted
    ///    (for instance, `:value` or `key:`).
    ///
    /// If the proprietary key does not have associated data, the third part of
    /// the descriptor must be fully omitted.
    WrongFormat(String),

    /// input at index {0} exceeds the number of inputs {1}
    InputOutOfRange(u16, usize),

    /// output at index {0} exceeds the number of outputs {1}
    OutputOutOfRange(u16, usize),
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum ProprietaryKeyLocation {
    #[display("global")]
    Global,

    #[display("input({0})")]
    Input(u16),

    #[display("output({0})")]
    Output(u16),
}

impl FromStr for ProprietaryKeyLocation {
    type Err = ProprietaryKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.trim_end_matches(')').split('(');
        match (
            split.next(),
            split.next().map(u16::from_str).transpose().ok().flatten(),
            split.next(),
        ) {
            (Some("global"), None, _) => Ok(ProprietaryKeyLocation::Global),
            (Some("input"), Some(pos), None) => Ok(ProprietaryKeyLocation::Input(pos)),
            (Some("output"), Some(pos), None) => Ok(ProprietaryKeyLocation::Output(pos)),
            _ => Err(ProprietaryKeyError::WrongLocation(s.to_owned())),
        }
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display("{prefix}({subtype})")]
pub struct ProprietaryKeyType {
    pub prefix: String,
    pub subtype: u8,
}

impl FromStr for ProprietaryKeyType {
    type Err = ProprietaryKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.trim_end_matches(')').split('(');
        match (
            split.next().map(str::to_owned),
            split.next().map(u8::from_str).transpose().ok().flatten(),
            split.next(),
        ) {
            (Some(prefix), Some(subtype), None) => Ok(ProprietaryKeyType { prefix, subtype }),
            _ => Err(ProprietaryKeyError::WrongType(s.to_owned())),
        }
    }
}

// --proprietary-key "input(1) DBC(1) 8536ba03:~"
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct ProprietaryKeyDescriptor {
    pub location: ProprietaryKeyLocation,
    pub ty: ProprietaryKeyType,
    pub key: Option<Vec<u8>>,
    pub value: Option<Vec<u8>>,
}

impl From<ProprietaryKeyDescriptor> for ProprietaryKey {
    fn from(key: ProprietaryKeyDescriptor) -> Self {
        ProprietaryKey::from(&key)
    }
}

impl From<&ProprietaryKeyDescriptor> for ProprietaryKey {
    fn from(key: &ProprietaryKeyDescriptor) -> Self {
        ProprietaryKey {
            prefix: key.ty.prefix.as_bytes().to_vec(),
            subtype: key.ty.subtype,
            key: key.key.as_ref().cloned().unwrap_or_default(),
        }
    }
}

impl FromStr for ProprietaryKeyDescriptor {
    type Err = ProprietaryKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = ProprietaryKeyError::WrongFormat(s.to_owned());
        let mut split = s.split_whitespace();
        match (
            split
                .next()
                .map(ProprietaryKeyLocation::from_str)
                .transpose()?,
            split.next().map(ProprietaryKeyType::from_str).transpose()?,
            split.next().and_then(|s| s.split_once(':')),
            split.next(),
        ) {
            (Some(location), Some(ty), None, None) => Ok(ProprietaryKeyDescriptor {
                location,
                ty,
                key: None,
                value: None,
            }),
            (Some(location), Some(ty), Some((k, v)), None) => Ok(ProprietaryKeyDescriptor {
                location,
                ty,
                key: if k.is_empty() {
                    None
                } else {
                    Some(Vec::from_hex(k).map_err(|_| err.clone())?)
                },
                value: if v.is_empty() {
                    None
                } else {
                    Some(Vec::from_hex(v).map_err(|_| err)?)
                },
            }),
            _ => Err(err),
        }
    }
}

impl Display for ProprietaryKeyDescriptor {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} ", self.location, self.ty)?;
        if (&self.key, &self.value) == (&None, &None) {
            return Ok(());
        }
        write!(
            f,
            "{}:{}",
            self.key.as_deref().map(<[u8]>::to_hex).unwrap_or_default(),
            self.value
                .as_deref()
                .map(<[u8]>::to_hex)
                .unwrap_or_default()
        )
    }
}
