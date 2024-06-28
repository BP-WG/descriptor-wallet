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

//! Bitcoin SLIP-132 standard implementation for parsing custom xpub/xpriv key
//! formats

// Coding conventions
#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code,
    missing_docs
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[macro_use]
extern crate amplify;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;

use std::fmt::Debug;
use std::str::FromStr;

use bitcoin::bip32::{self, ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::{base58, Network};

/// Magical version bytes for xpub: bitcoin mainnet public key for P2PKH or P2SH
pub const VERSION_MAGIC_XPUB: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
/// Magical version bytes for xprv: bitcoin mainnet private key for P2PKH or
/// P2SH
pub const VERSION_MAGIC_XPRV: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];
/// Magical version bytes for ypub: bitcoin mainnet public key for P2WPKH in
/// P2SH
pub const VERSION_MAGIC_YPUB: [u8; 4] = [0x04, 0x9D, 0x7C, 0xB2];
/// Magical version bytes for yprv: bitcoin mainnet private key for P2WPKH in
/// P2SH
pub const VERSION_MAGIC_YPRV: [u8; 4] = [0x04, 0x9D, 0x78, 0x78];
/// Magical version bytes for zpub: bitcoin mainnet public key for P2WPKH
pub const VERSION_MAGIC_ZPUB: [u8; 4] = [0x04, 0xB2, 0x47, 0x46];
/// Magical version bytes for zprv: bitcoin mainnet private key for P2WPKH
pub const VERSION_MAGIC_ZPRV: [u8; 4] = [0x04, 0xB2, 0x43, 0x0C];
/// Magical version bytes for Ypub: bitcoin mainnet public key for
/// multi-signature P2WSH in P2SH
pub const VERSION_MAGIC_YPUB_MULTISIG: [u8; 4] = [0x02, 0x95, 0xb4, 0x3f];
/// Magical version bytes for Yprv: bitcoin mainnet private key for
/// multi-signature P2WSH in P2SH
pub const VERSION_MAGIC_YPRV_MULTISIG: [u8; 4] = [0x02, 0x95, 0xb0, 0x05];
/// Magical version bytes for Zpub: bitcoin mainnet public key for
/// multi-signature P2WSH
pub const VERSION_MAGIC_ZPUB_MULTISIG: [u8; 4] = [0x02, 0xaa, 0x7e, 0xd3];
/// Magical version bytes for Zprv: bitcoin mainnet private key for
/// multi-signature P2WSH
pub const VERSION_MAGIC_ZPRV_MULTISIG: [u8; 4] = [0x02, 0xaa, 0x7a, 0x99];

/// Magical version bytes for tpub: bitcoin testnet/regtest public key for
/// P2PKH or P2SH
pub const VERSION_MAGIC_TPUB: [u8; 4] = [0x04, 0x35, 0x87, 0xCF];
/// Magical version bytes for tprv: bitcoin testnet/regtest private key for
/// P2PKH or P2SH
pub const VERSION_MAGIC_TPRV: [u8; 4] = [0x04, 0x35, 0x83, 0x94];
/// Magical version bytes for upub: bitcoin testnet/regtest public key for
/// P2WPKH in P2SH
pub const VERSION_MAGIC_UPUB: [u8; 4] = [0x04, 0x4A, 0x52, 0x62];
/// Magical version bytes for uprv: bitcoin testnet/regtest private key for
/// P2WPKH in P2SH
pub const VERSION_MAGIC_UPRV: [u8; 4] = [0x04, 0x4A, 0x4E, 0x28];
/// Magical version bytes for vpub: bitcoin testnet/regtest public key for
/// P2WPKH
pub const VERSION_MAGIC_VPUB: [u8; 4] = [0x04, 0x5F, 0x1C, 0xF6];
/// Magical version bytes for vprv: bitcoin testnet/regtest private key for
/// P2WPKH
pub const VERSION_MAGIC_VPRV: [u8; 4] = [0x04, 0x5F, 0x18, 0xBC];
/// Magical version bytes for Upub: bitcoin testnet/regtest public key for
/// multi-signature P2WSH in P2SH
pub const VERSION_MAGIC_UPUB_MULTISIG: [u8; 4] = [0x02, 0x42, 0x89, 0xef];
/// Magical version bytes for Uprv: bitcoin testnet/regtest private key for
/// multi-signature P2WSH in P2SH
pub const VERSION_MAGIC_UPRV_MULTISIG: [u8; 4] = [0x02, 0x42, 0x85, 0xb5];
/// Magical version bytes for Zpub: bitcoin testnet/regtest public key for
/// multi-signature P2WSH
pub const VERSION_MAGIC_VPUB_MULTISIG: [u8; 4] = [0x02, 0x57, 0x54, 0x83];
/// Magical version bytes for Zprv: bitcoin testnet/regtest private key for
/// multi-signature P2WSH
pub const VERSION_MAGIC_VPRV_MULTISIG: [u8; 4] = [0x02, 0x57, 0x50, 0x48];

/// Extended public and private key processing errors
#[derive(Clone, PartialEq, Eq, Debug, Display, From, Error)]
#[display(doc_comments)]
pub enum Error {
    /// error in BASE58 key encoding. Details: {0}
    #[from]
    Base58(base58::Error),

    /// invalid character in Base58 encoding
    #[from]
    #[display(inner)]
    InvalidCharacterError(InvalidCharacterError),

    /// error in hex key encoding. Details: {0}
    #[from]
    Hex(HexToArrayError),

    /// pk->pk derivation was attempted on a hardened key.
    CannotDeriveFromHardenedKey,

    /// child number {0} is out of range.
    InvalidChildNumber(u32),

    /// invalid child number format.
    InvalidChildNumberFormat,

    /// invalid derivation path format.
    InvalidDerivationPathFormat,

    /// unknown version magic bytes {0:#06X?}
    UnknownVersion([u8; 4]),

    /// encoded extended key data has wrong length {0}
    WrongExtendedKeyLength(usize),

    /// unrecognized or unsupported extended key prefix (please check SLIP 32
    /// for possible values)
    UnknownSlip32Prefix,

    /// failure in rust bitcoin library
    InternalFailure,
}

impl From<bip32::Error> for Error {
    fn from(err: bip32::Error) -> Self {
        match err {
            bip32::Error::CannotDeriveFromHardenedKey => Error::CannotDeriveFromHardenedKey,
            bip32::Error::InvalidChildNumber(no) => Error::InvalidChildNumber(no),
            bip32::Error::InvalidChildNumberFormat => Error::InvalidChildNumberFormat,
            bip32::Error::InvalidDerivationPathFormat => Error::InvalidDerivationPathFormat,
            bip32::Error::Secp256k1(_) => Error::InternalFailure,
            bip32::Error::UnknownVersion(ver) => Error::UnknownVersion(ver),
            bip32::Error::WrongExtendedKeyLength(len) => Error::WrongExtendedKeyLength(len),
            bip32::Error::Base58(err) => Error::Base58(err),
            bip32::Error::Hex(err) => Error::Hex(err),
            _ => Error::InternalFailure,
        }
    }
}

/// Structure holding 4 version bytes with magical numbers representing
/// different versions of extended public and private keys according to BIP-32.
/// Key version stores raw bytes without their check, interpretation or
/// verification; for these purposes special helpers structures implementing
/// [`VersionResolver`] are used.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct KeyVersion([u8; 4]);

/// Trait which must be implemented by helpers which do construction,
/// interpretation, verification and cross-conversion of extended public and
/// private key version magic bytes from [`KeyVersion`]
pub trait VersionResolver:
    Copy + Clone + PartialEq + Eq + PartialOrd + Ord + std::hash::Hash + Debug
{
    /// Type that defines recognized network options
    type Network;

    /// Type that defines possible applications fro public and private keys
    /// (types of scriptPubkey descriptors in which they can be used)
    type Application;

    /// Constructor for [`KeyVersion`] with given network, application scope and
    /// key type (public or private)
    fn resolve(
        network: Self::Network,
        applicable_for: Self::Application,
        is_priv: bool,
    ) -> KeyVersion;

    /// Detects whether provided version corresponds to an extended public key.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    fn is_pub(_: &KeyVersion) -> Option<bool> { None }

    /// Detects whether provided version corresponds to an extended private key.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    fn is_prv(_: &KeyVersion) -> Option<bool> { None }

    /// Detects network used by the provided key version bytes.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    fn network(_: &KeyVersion) -> Option<Self::Network> { None }

    /// Detects application scope defined by the provided key version bytes.
    /// Application scope is a types of scriptPubkey descriptors in which given
    /// extended public/private keys can be used.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    fn application(_: &KeyVersion) -> Option<Self::Application> { None }

    /// Returns BIP 32 derivation path for the provided key version.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    fn derivation_path(_: &KeyVersion, _: Option<ChildNumber>) -> Option<DerivationPath> { None }

    /// Converts version into version corresponding to an extended public key.
    /// Returns `None` if the resolver does not know how to perform conversion.
    fn make_pub(_: &KeyVersion) -> Option<KeyVersion> { None }

    /// Converts version into version corresponding to an extended private key.
    /// Returns `None` if the resolver does not know how to perform conversion.
    fn make_prv(_: &KeyVersion) -> Option<KeyVersion> { None }
}

impl KeyVersion {
    /// Detects whether provided version corresponds to an extended public key.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    pub fn is_pub<R: VersionResolver>(&self) -> Option<bool> { R::is_pub(self) }

    /// Detects whether provided version corresponds to an extended private key.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    pub fn is_prv<R: VersionResolver>(&self) -> Option<bool> { R::is_prv(self) }

    /// Detects network used by the provided key version bytes.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    pub fn network<R: VersionResolver>(&self) -> Option<R::Network> { R::network(self) }

    /// Detects application scope defined by the provided key version bytes.
    /// Application scope is a types of scriptPubkey descriptors in which given
    /// extended public/private keys can be used.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    pub fn application<R: VersionResolver>(&self) -> Option<R::Application> { R::application(self) }

    /// Returns BIP 32 derivation path for the provided key version.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    pub fn derivation_path<R: VersionResolver>(
        &self,
        account: Option<ChildNumber>,
    ) -> Option<DerivationPath> {
        R::derivation_path(self, account)
    }

    /// Converts version into version corresponding to an extended public key.
    /// Returns `None` if the resolver does not know how to perform conversion.
    pub fn try_to_pub<R: VersionResolver>(&self) -> Option<KeyVersion> { R::make_pub(self) }

    /// Converts version into version corresponding to an extended private key.
    /// Returns `None` if the resolver does not know how to perform conversion.
    pub fn try_to_prv<R: VersionResolver>(&self) -> Option<KeyVersion> { R::make_prv(self) }
}

/// Default resolver knowing native [`bitcoin::network::constants::Network`]
/// and BIP 32 and SLIP 132-defined key applications with [`KeyApplication`]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct DefaultResolver;

/// SLIP 132-defined key applications defining types of scriptPubkey descriptors
/// in which they can be used
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[non_exhaustive]
pub enum KeyApplication {
    /// xprv/xpub: keys that can be used for P2PKH and multisig P2SH
    /// scriptPubkey descriptors.
    #[display("BIP44")]
    #[cfg_attr(feature = "serde", serde(rename = "bip44"))]
    Hashed,

    /// zprv/zpub: keys that can be used for P2WPKH scriptPubkey descriptors
    #[display("BIP84")]
    #[cfg_attr(feature = "serde", serde(rename = "bip84"))]
    SegWit,

    /// Zprv/Zpub: keys that can be used for multisig P2WSH scriptPubkey
    /// descriptors
    #[display("BIP48-native")]
    #[cfg_attr(feature = "serde", serde(rename = "bip48-native"))]
    SegWitMultisig,

    /// yprv/ypub: keys that can be used for P2WPKH-in-P2SH scriptPubkey
    /// descriptors
    #[display("BIP49")]
    #[cfg_attr(feature = "serde", serde(rename = "bip49"))]
    Nested,

    /// Yprv/Ypub: keys that can be used for multisig P2WSH-in-P2SH
    /// scriptPubkey descriptors
    #[display("BIP48-nested")]
    #[cfg_attr(feature = "serde", serde(rename = "bip48-nested"))]
    NestedMultisig,
}

/// Unknown string representation of [`KeyApplication`] enum
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error
)]
#[display(doc_comments)]
pub struct UnknownKeyApplicationError;

impl FromStr for KeyApplication {
    type Err = UnknownKeyApplicationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "bip44" => KeyApplication::Hashed,
            "bip84" => KeyApplication::SegWit,
            "bip48-native" => KeyApplication::SegWitMultisig,
            "bip49" => KeyApplication::Nested,
            "bip48-nested" => KeyApplication::NestedMultisig,
            _ => return Err(UnknownKeyApplicationError),
        })
    }
}

impl KeyApplication {
    /// Enumerates all application variants    
    pub const ALL: [KeyApplication; 5] = [
        KeyApplication::Hashed,
        KeyApplication::SegWit,
        KeyApplication::SegWitMultisig,
        KeyApplication::Nested,
        KeyApplication::NestedMultisig,
    ];

    /// Deduces application variant corresponding to the provided derivation
    /// path, if possible.
    pub fn from_derivation_path(path: DerivationPath) -> Option<KeyApplication> {
        let path: Vec<_> = path.into();
        for application in &Self::ALL {
            if let Some(standard) = application.to_derivation_path() {
                let standard: Vec<_> = standard.into();
                if path.strip_prefix(standard.as_slice()).is_some() {
                    return Some(*application);
                }
            }
        }
        let bip48_purpose = ChildNumber::Hardened { index: 48 };
        if path.len() >= 4 && path[0] == bip48_purpose {
            match path[3] {
                ChildNumber::Hardened { index: 1 } => Some(KeyApplication::NestedMultisig),
                ChildNumber::Hardened { index: 2 } => Some(KeyApplication::SegWitMultisig),
                _ => None,
            }
        } else {
            None
        }
    }

    /// Constructs derivation path matching the provided application
    pub fn to_derivation_path(&self) -> Option<DerivationPath> {
        match self {
            Self::Hashed => Some(DerivationPath::from(vec![ChildNumber::Hardened {
                index: 44,
            }])),
            Self::Nested => Some(DerivationPath::from(vec![ChildNumber::Hardened {
                index: 49,
            }])),
            Self::SegWit => Some(DerivationPath::from(vec![ChildNumber::Hardened {
                index: 84,
            }])),
            _ => None, // No Multisig?
        }
    }
}

impl KeyVersion {
    /// Tries to construct [`KeyVersion`] object from a byte slice. If byte
    /// slice length is not equal to 4, returns `None`
    pub fn from_slice(version_slice: &[u8]) -> Option<KeyVersion> {
        if version_slice.len() != 4 {
            return None;
        }
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(version_slice);
        Some(KeyVersion::from_bytes(bytes))
    }

    /// Constructs [`KeyVersion`] from a Base58-encoded extended key string.
    ///
    /// # Panics
    /// If the string does not contain at least 5 characters.
    #[inline]
    pub fn from_xkey_str(key: &str) -> Result<KeyVersion, Error> {
        let xkey = base58::decode(key)?;
        KeyVersion::from_slice(&xkey[..4]).ok_or(Error::UnknownSlip32Prefix)
    }

    /// Constructs [`KeyVersion`] from a fixed 4 bytes values
    pub fn from_bytes(version_bytes: [u8; 4]) -> KeyVersion { KeyVersion(version_bytes) }

    /// Constructs [`KeyVersion`] from a `u32`-representation of the version
    /// bytes (the representation must be in bing endian format)
    pub fn from_u32(version: u32) -> KeyVersion { KeyVersion(version.to_be_bytes()) }

    /// Converts version bytes into `u32` representation in big endian format
    pub fn to_u32(&self) -> u32 { u32::from_be_bytes(self.0) }

    /// Returns slice representing internal version bytes
    pub fn as_slice(&self) -> &[u8] { &self.0 }

    /// Returns internal representation of version bytes
    pub fn as_bytes(&self) -> &[u8; 4] { &self.0 }

    /// Constructs 4-byte array containing version byte values
    pub fn to_bytes(&self) -> [u8; 4] { self.0 }

    /// Converts into 4-byte array containing version byte values
    pub fn into_bytes(self) -> [u8; 4] { self.0 }
}

impl VersionResolver for DefaultResolver {
    type Network = Network;
    type Application = KeyApplication;

    fn resolve(
        network: Self::Network,
        applicable_for: Self::Application,
        is_priv: bool,
    ) -> KeyVersion {
        match (network, applicable_for, is_priv) {
            (Network::Bitcoin, KeyApplication::Hashed, false) => KeyVersion(VERSION_MAGIC_XPUB),
            (Network::Bitcoin, KeyApplication::Hashed, true) => KeyVersion(VERSION_MAGIC_XPRV),
            (Network::Bitcoin, KeyApplication::Nested, false) => KeyVersion(VERSION_MAGIC_YPUB),
            (Network::Bitcoin, KeyApplication::Nested, true) => KeyVersion(VERSION_MAGIC_YPRV),
            (Network::Bitcoin, KeyApplication::SegWit, false) => KeyVersion(VERSION_MAGIC_ZPUB),
            (Network::Bitcoin, KeyApplication::SegWit, true) => KeyVersion(VERSION_MAGIC_ZPRV),
            (Network::Bitcoin, KeyApplication::NestedMultisig, false) => {
                KeyVersion(VERSION_MAGIC_YPUB_MULTISIG)
            }
            (Network::Bitcoin, KeyApplication::NestedMultisig, true) => {
                KeyVersion(VERSION_MAGIC_YPRV_MULTISIG)
            }
            (Network::Bitcoin, KeyApplication::SegWitMultisig, false) => {
                KeyVersion(VERSION_MAGIC_ZPUB_MULTISIG)
            }
            (Network::Bitcoin, KeyApplication::SegWitMultisig, true) => {
                KeyVersion(VERSION_MAGIC_ZPRV_MULTISIG)
            }
            (_, KeyApplication::Hashed, false) => KeyVersion(VERSION_MAGIC_TPUB),
            (_, KeyApplication::Hashed, true) => KeyVersion(VERSION_MAGIC_TPRV),
            (_, KeyApplication::Nested, false) => KeyVersion(VERSION_MAGIC_UPUB),
            (_, KeyApplication::Nested, true) => KeyVersion(VERSION_MAGIC_UPRV),
            (_, KeyApplication::SegWit, false) => KeyVersion(VERSION_MAGIC_VPUB),
            (_, KeyApplication::SegWit, true) => KeyVersion(VERSION_MAGIC_VPRV),
            (_, KeyApplication::NestedMultisig, false) => KeyVersion(VERSION_MAGIC_UPUB_MULTISIG),
            (_, KeyApplication::NestedMultisig, true) => KeyVersion(VERSION_MAGIC_UPRV_MULTISIG),
            (_, KeyApplication::SegWitMultisig, false) => KeyVersion(VERSION_MAGIC_VPUB_MULTISIG),
            (_, KeyApplication::SegWitMultisig, true) => KeyVersion(VERSION_MAGIC_VPRV_MULTISIG),
        }
    }

    fn is_pub(kv: &KeyVersion) -> Option<bool> {
        match kv.as_bytes() {
            &VERSION_MAGIC_XPUB
            | &VERSION_MAGIC_YPUB
            | &VERSION_MAGIC_ZPUB
            | &VERSION_MAGIC_TPUB
            | &VERSION_MAGIC_UPUB
            | &VERSION_MAGIC_VPUB
            | &VERSION_MAGIC_YPUB_MULTISIG
            | &VERSION_MAGIC_ZPUB_MULTISIG
            | &VERSION_MAGIC_UPUB_MULTISIG
            | &VERSION_MAGIC_VPUB_MULTISIG => Some(true),
            &VERSION_MAGIC_XPRV
            | &VERSION_MAGIC_YPRV
            | &VERSION_MAGIC_ZPRV
            | &VERSION_MAGIC_TPRV
            | &VERSION_MAGIC_UPRV
            | &VERSION_MAGIC_VPRV
            | &VERSION_MAGIC_YPRV_MULTISIG
            | &VERSION_MAGIC_ZPRV_MULTISIG
            | &VERSION_MAGIC_UPRV_MULTISIG
            | &VERSION_MAGIC_VPRV_MULTISIG => Some(false),
            _ => None,
        }
    }

    fn is_prv(kv: &KeyVersion) -> Option<bool> { DefaultResolver::is_pub(kv).map(|v| !v) }

    fn network(kv: &KeyVersion) -> Option<Self::Network> {
        match kv.as_bytes() {
            &VERSION_MAGIC_XPRV
            | &VERSION_MAGIC_XPUB
            | &VERSION_MAGIC_YPRV
            | &VERSION_MAGIC_YPUB
            | &VERSION_MAGIC_ZPRV
            | &VERSION_MAGIC_ZPUB
            | &VERSION_MAGIC_YPRV_MULTISIG
            | &VERSION_MAGIC_YPUB_MULTISIG
            | &VERSION_MAGIC_ZPRV_MULTISIG
            | &VERSION_MAGIC_ZPUB_MULTISIG => Some(Network::Bitcoin),
            &VERSION_MAGIC_TPRV
            | &VERSION_MAGIC_TPUB
            | &VERSION_MAGIC_UPRV
            | &VERSION_MAGIC_UPUB
            | &VERSION_MAGIC_VPRV
            | &VERSION_MAGIC_VPUB
            | &VERSION_MAGIC_UPRV_MULTISIG
            | &VERSION_MAGIC_UPUB_MULTISIG
            | &VERSION_MAGIC_VPRV_MULTISIG
            | &VERSION_MAGIC_VPUB_MULTISIG => Some(Network::Testnet),
            _ => None,
        }
    }

    fn application(kv: &KeyVersion) -> Option<Self::Application> {
        match kv.as_bytes() {
            &VERSION_MAGIC_XPUB | &VERSION_MAGIC_XPRV | &VERSION_MAGIC_TPUB
            | &VERSION_MAGIC_TPRV => None,
            &VERSION_MAGIC_YPUB | &VERSION_MAGIC_YPRV | &VERSION_MAGIC_UPUB
            | &VERSION_MAGIC_UPRV => Some(KeyApplication::Nested),
            &VERSION_MAGIC_YPUB_MULTISIG
            | &VERSION_MAGIC_YPRV_MULTISIG
            | &VERSION_MAGIC_UPUB_MULTISIG
            | &VERSION_MAGIC_UPRV_MULTISIG => Some(KeyApplication::NestedMultisig),
            &VERSION_MAGIC_ZPUB | &VERSION_MAGIC_ZPRV | &VERSION_MAGIC_VPUB
            | &VERSION_MAGIC_VPRV => Some(KeyApplication::SegWit),
            &VERSION_MAGIC_ZPUB_MULTISIG
            | &VERSION_MAGIC_ZPRV_MULTISIG
            | &VERSION_MAGIC_VPUB_MULTISIG
            | &VERSION_MAGIC_VPRV_MULTISIG => Some(KeyApplication::SegWitMultisig),
            _ => None,
        }
    }

    fn derivation_path(kv: &KeyVersion, account: Option<ChildNumber>) -> Option<DerivationPath> {
        match kv.as_bytes() {
            &VERSION_MAGIC_XPUB | &VERSION_MAGIC_XPRV => None,
            &VERSION_MAGIC_TPUB | &VERSION_MAGIC_TPRV => None,
            &VERSION_MAGIC_YPUB | &VERSION_MAGIC_YPRV => Some(vec![
                ChildNumber::Hardened { index: 49 },
                ChildNumber::Hardened { index: 0 },
            ]),
            &VERSION_MAGIC_UPUB | &VERSION_MAGIC_UPRV => Some(vec![
                ChildNumber::Hardened { index: 49 },
                ChildNumber::Hardened { index: 1 },
            ]),
            &VERSION_MAGIC_ZPUB | &VERSION_MAGIC_ZPRV => Some(vec![
                ChildNumber::Hardened { index: 84 },
                ChildNumber::Hardened { index: 0 },
            ]),
            &VERSION_MAGIC_VPUB | &VERSION_MAGIC_VPRV => Some(vec![
                ChildNumber::Hardened { index: 84 },
                ChildNumber::Hardened { index: 1 },
            ]),
            &VERSION_MAGIC_ZPUB_MULTISIG
            | &VERSION_MAGIC_ZPRV_MULTISIG
            | &VERSION_MAGIC_YPUB_MULTISIG
            | &VERSION_MAGIC_YPRV_MULTISIG
                if account.is_some() =>
            {
                Some(vec![
                    ChildNumber::Hardened { index: 48 },
                    ChildNumber::Hardened { index: 0 },
                ])
            }
            &VERSION_MAGIC_UPUB_MULTISIG
            | &VERSION_MAGIC_UPRV_MULTISIG
            | &VERSION_MAGIC_VPUB_MULTISIG
            | &VERSION_MAGIC_VPRV_MULTISIG
                if account.is_some() =>
            {
                Some(vec![
                    ChildNumber::Hardened { index: 48 },
                    ChildNumber::Hardened { index: 1 },
                ])
            }
            _ => None,
        }
        .map(|mut path| {
            if let Some(account_index) = account {
                path.push(account_index);
                match kv.as_bytes() {
                    &VERSION_MAGIC_ZPUB_MULTISIG
                    | &VERSION_MAGIC_ZPRV_MULTISIG
                    | &VERSION_MAGIC_VPUB_MULTISIG
                    | &VERSION_MAGIC_VPRV_MULTISIG => path.push(ChildNumber::Hardened { index: 2 }),
                    &VERSION_MAGIC_YPUB_MULTISIG
                    | &VERSION_MAGIC_YPRV_MULTISIG
                    | &VERSION_MAGIC_UPUB_MULTISIG
                    | &VERSION_MAGIC_UPRV_MULTISIG => path.push(ChildNumber::Hardened { index: 1 }),
                    _ => {}
                }
            }
            DerivationPath::from(path)
        })
    }

    fn make_pub(kv: &KeyVersion) -> Option<KeyVersion> {
        match kv.as_bytes() {
            &VERSION_MAGIC_XPRV => Some(KeyVersion::from_bytes(VERSION_MAGIC_XPUB)),
            &VERSION_MAGIC_YPRV => Some(KeyVersion::from_bytes(VERSION_MAGIC_YPUB)),
            &VERSION_MAGIC_ZPRV => Some(KeyVersion::from_bytes(VERSION_MAGIC_ZPUB)),
            &VERSION_MAGIC_TPRV => Some(KeyVersion::from_bytes(VERSION_MAGIC_TPUB)),
            &VERSION_MAGIC_UPRV => Some(KeyVersion::from_bytes(VERSION_MAGIC_UPUB)),
            &VERSION_MAGIC_VPRV => Some(KeyVersion::from_bytes(VERSION_MAGIC_VPUB)),
            &VERSION_MAGIC_YPRV_MULTISIG => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_YPUB_MULTISIG))
            }
            &VERSION_MAGIC_ZPRV_MULTISIG => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_ZPUB_MULTISIG))
            }
            &VERSION_MAGIC_UPRV_MULTISIG => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_UPUB_MULTISIG))
            }
            &VERSION_MAGIC_VPRV_MULTISIG => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_VPUB_MULTISIG))
            }
            &VERSION_MAGIC_XPUB
            | &VERSION_MAGIC_YPUB
            | &VERSION_MAGIC_ZPUB
            | &VERSION_MAGIC_TPUB
            | &VERSION_MAGIC_UPUB
            | &VERSION_MAGIC_VPUB
            | &VERSION_MAGIC_YPUB_MULTISIG
            | &VERSION_MAGIC_ZPUB_MULTISIG
            | &VERSION_MAGIC_UPUB_MULTISIG
            | &VERSION_MAGIC_VPUB_MULTISIG => Some(*kv),
            _ => None,
        }
    }

    fn make_prv(kv: &KeyVersion) -> Option<KeyVersion> {
        match kv.as_bytes() {
            &VERSION_MAGIC_XPUB => Some(KeyVersion::from_bytes(VERSION_MAGIC_XPRV)),
            &VERSION_MAGIC_YPUB => Some(KeyVersion::from_bytes(VERSION_MAGIC_YPRV)),
            &VERSION_MAGIC_ZPUB => Some(KeyVersion::from_bytes(VERSION_MAGIC_ZPRV)),
            &VERSION_MAGIC_TPUB => Some(KeyVersion::from_bytes(VERSION_MAGIC_TPRV)),
            &VERSION_MAGIC_UPUB => Some(KeyVersion::from_bytes(VERSION_MAGIC_UPRV)),
            &VERSION_MAGIC_VPUB => Some(KeyVersion::from_bytes(VERSION_MAGIC_VPRV)),
            &VERSION_MAGIC_YPUB_MULTISIG => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_YPRV_MULTISIG))
            }
            &VERSION_MAGIC_ZPUB_MULTISIG => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_ZPRV_MULTISIG))
            }
            &VERSION_MAGIC_UPUB_MULTISIG => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_UPRV_MULTISIG))
            }
            &VERSION_MAGIC_VPUB_MULTISIG => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_VPRV_MULTISIG))
            }
            &VERSION_MAGIC_XPRV
            | &VERSION_MAGIC_YPRV
            | &VERSION_MAGIC_ZPRV
            | &VERSION_MAGIC_TPRV
            | &VERSION_MAGIC_UPRV
            | &VERSION_MAGIC_VPRV
            | &VERSION_MAGIC_YPRV_MULTISIG
            | &VERSION_MAGIC_ZPRV_MULTISIG
            | &VERSION_MAGIC_UPRV_MULTISIG
            | &VERSION_MAGIC_VPRV_MULTISIG => Some(*kv),
            _ => None,
        }
    }
}

/// Trait for building standard BIP32 extended keys from SLIP132 variant.
pub trait FromSlip132 {
    /// Constructs standard BIP32 extended key from SLIP132 string.
    fn from_slip132_str(s: &str) -> Result<Self, Error>
    where
        Self: Sized;
}

impl FromSlip132 for Xpub {
    fn from_slip132_str(s: &str) -> Result<Self, Error> {
        let mut data = base58::decode_check(s)?;

        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&data[0..4]);
        let slice = match prefix {
            VERSION_MAGIC_XPUB
            | VERSION_MAGIC_YPUB
            | VERSION_MAGIC_ZPUB
            | VERSION_MAGIC_YPUB_MULTISIG
            | VERSION_MAGIC_ZPUB_MULTISIG => VERSION_MAGIC_XPUB,

            VERSION_MAGIC_TPUB
            | VERSION_MAGIC_UPUB
            | VERSION_MAGIC_VPUB
            | VERSION_MAGIC_UPUB_MULTISIG
            | VERSION_MAGIC_VPUB_MULTISIG => VERSION_MAGIC_TPUB,

            _ => return Err(Error::UnknownSlip32Prefix),
        };
        data[0..4].copy_from_slice(&slice);

        let xpub = Xpub::decode(&data)?;

        Ok(xpub)
    }
}

impl FromSlip132 for Xpriv {
    fn from_slip132_str(s: &str) -> Result<Self, Error> {
        let mut data = base58::decode_check(s)?;

        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&data[0..4]);
        let slice = match prefix {
            VERSION_MAGIC_XPRV
            | VERSION_MAGIC_YPRV
            | VERSION_MAGIC_ZPRV
            | VERSION_MAGIC_YPRV_MULTISIG
            | VERSION_MAGIC_ZPRV_MULTISIG => VERSION_MAGIC_XPRV,

            VERSION_MAGIC_TPRV
            | VERSION_MAGIC_UPRV
            | VERSION_MAGIC_VPRV
            | VERSION_MAGIC_UPRV_MULTISIG
            | VERSION_MAGIC_VPRV_MULTISIG => VERSION_MAGIC_TPRV,

            _ => return Err(Error::UnknownSlip32Prefix),
        };
        data[0..4].copy_from_slice(&slice);

        let xprv = Xpriv::decode(&data)?;

        Ok(xprv)
    }
}

/// Trait converting standard BIP32 extended keys into SLIP132 representation.
pub trait ToSlip132 {
    /// Creates SLIP132 key representation matching the provided application
    /// and bitcoin network.
    fn to_slip132_string(&self, key_application: KeyApplication, network: Network) -> String;
}

impl ToSlip132 for Xpub {
    fn to_slip132_string(&self, key_application: KeyApplication, network: Network) -> String {
        let key_version = DefaultResolver::resolve(network, key_application, false);
        let mut xpub = self.encode();
        xpub[0..4].copy_from_slice(key_version.as_slice());
        base58::encode_check(&xpub)
    }
}

impl ToSlip132 for Xpriv {
    fn to_slip132_string(&self, key_application: KeyApplication, network: Network) -> String {
        let key_version = DefaultResolver::resolve(network, key_application, true);
        let mut xpriv = self.encode();
        xpriv[0..4].copy_from_slice(key_version.as_slice());
        base58::encode_check(&xpriv)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn key_application_from_str() {
        assert_eq!(
            KeyApplication::from_str("bip44"),
            Ok(KeyApplication::Hashed)
        );
        assert_eq!(
            KeyApplication::from_str("bip84"),
            Ok(KeyApplication::SegWit)
        );
        assert_eq!(
            KeyApplication::from_str("bip48-native"),
            Ok(KeyApplication::SegWitMultisig)
        );
        assert_eq!(
            KeyApplication::from_str("bip49"),
            Ok(KeyApplication::Nested)
        );
        assert_eq!(
            KeyApplication::from_str("bip48-nested"),
            Ok(KeyApplication::NestedMultisig)
        );
        assert_eq!(
            KeyApplication::from_str("bip"),
            Err(UnknownKeyApplicationError)
        );
    }

    #[test]
    fn key_application_from_derivation_path() {
        // Mainnet
        assert_eq!(
            KeyApplication::from_derivation_path("m/44'/0'/3'".parse().unwrap()),
            Some(KeyApplication::Hashed)
        );
        assert_eq!(
            KeyApplication::from_derivation_path("m/49'/0'/5'".parse().unwrap()),
            Some(KeyApplication::Nested)
        );
        assert_eq!(
            KeyApplication::from_derivation_path("m/48'/0'/8'/1'".parse().unwrap()),
            Some(KeyApplication::NestedMultisig)
        );
        assert_eq!(
            KeyApplication::from_derivation_path("m/84'/0'/13'".parse().unwrap()),
            Some(KeyApplication::SegWit)
        );
        assert_eq!(
            KeyApplication::from_derivation_path("m/48'/0'/21'/2'".parse().unwrap()),
            Some(KeyApplication::SegWitMultisig)
        );

        // Testnet
        assert_eq!(
            KeyApplication::from_derivation_path("m/44'/1'/34'".parse().unwrap()),
            Some(KeyApplication::Hashed)
        );
        assert_eq!(
            KeyApplication::from_derivation_path("m/49'/1'/55'".parse().unwrap()),
            Some(KeyApplication::Nested)
        );
        assert_eq!(
            KeyApplication::from_derivation_path("m/48'/1'/89'/1'".parse().unwrap()),
            Some(KeyApplication::NestedMultisig)
        );
        assert_eq!(
            KeyApplication::from_derivation_path("m/84'/1'/144'".parse().unwrap()),
            Some(KeyApplication::SegWit)
        );
        assert_eq!(
            KeyApplication::from_derivation_path("m/48'/1'/233'/2'".parse().unwrap()),
            Some(KeyApplication::SegWitMultisig)
        );

        // Unknown application 6'
        assert_eq!(
            KeyApplication::from_derivation_path("m/6'/0'/233'".parse().unwrap()),
            None
        );

        // Unknown script type 21'
        assert_eq!(
            KeyApplication::from_derivation_path("m/48'/0'/0'/21'".parse().unwrap()),
            None
        );
    }

    #[test]
    fn key_application_to_derivation_path() {
        assert_eq!(
            KeyApplication::Hashed.to_derivation_path(),
            Some(DerivationPath::from_str("m/44'").unwrap())
        );
        assert_eq!(
            KeyApplication::Nested.to_derivation_path(),
            Some(DerivationPath::from_str("m/49'").unwrap())
        );
        assert_eq!(
            KeyApplication::SegWit.to_derivation_path(),
            Some(DerivationPath::from_str("m/84'").unwrap())
        );
        assert_eq!(KeyApplication::NestedMultisig.to_derivation_path(), None);
        assert_eq!(KeyApplication::SegWitMultisig.to_derivation_path(), None);
    }

    #[test]
    fn key_version_from_slice() {
        let bytes = [0, 2, 4, 8];
        assert_eq!(
            KeyVersion::from_slice(&bytes[0..4]),
            Some(KeyVersion(bytes))
        );

        // Too short
        assert!(KeyVersion::from_slice(&bytes[0..3]).is_none());

        // Too long
        assert!(KeyVersion::from_slice(&[0, 1, 2, 3, 4]).is_none());
    }

    #[test]
    fn key_version_from_xkey_str() {
        let zpub = "zpub6qUQGY8YyN3ZztQBDdN8gUrFNvgCdTdFyTNorQ79VfkfkmhMR6D4cHBZ4EnXdFog1e2ugyCJqTcyDE4ZpTGqcMiCEnyPEyJFKbPVL9knhKU";
        assert_eq!(
            KeyVersion::from_xkey_str(zpub),
            Ok(KeyVersion(VERSION_MAGIC_ZPUB))
        );
    }

    #[test]
    fn key_version_from_bytes() {
        let bytes = [0, 2, 4, 8];
        assert_eq!(KeyVersion::from_bytes(bytes), KeyVersion(bytes));
    }

    #[test]
    fn key_version_from_u32() {
        let be_u32 = 132104;
        assert_eq!(
            KeyVersion::from_u32(be_u32),
            KeyVersion(be_u32.to_be_bytes())
        );
    }

    #[test]
    fn key_version_to_u32() {
        let bytes = [0, 2, 4, 8];
        let be_u32 = u32::from_be_bytes(bytes);
        assert_eq!(KeyVersion(bytes).to_u32(), be_u32);
    }

    #[test]
    fn key_version_as_slice() {
        let bytes = [0, 2, 4, 8];
        assert_eq!(KeyVersion(bytes).as_slice(), bytes);
    }

    #[test]
    fn key_version_as_bytes() {
        let bytes = [0, 2, 4, 8];
        assert_eq!(KeyVersion(bytes).as_bytes(), &bytes);
    }

    #[test]
    fn key_version_to_bytes() {
        let bytes = [0, 2, 4, 8];
        assert_eq!(KeyVersion(bytes).to_bytes(), bytes);
    }

    #[test]
    fn key_version_into_bytes() {
        let bytes = [0, 2, 4, 8];
        assert_eq!(KeyVersion(bytes).into_bytes(), bytes);
    }

    #[test]
    fn default_resolver_resolve() {
        assert_eq!(
            DefaultResolver::resolve(Network::Testnet, KeyApplication::Hashed, true),
            KeyVersion(VERSION_MAGIC_TPRV)
        );
        assert_eq!(
            DefaultResolver::resolve(Network::Testnet, KeyApplication::Hashed, false),
            KeyVersion(VERSION_MAGIC_TPUB)
        );

        assert_eq!(
            DefaultResolver::resolve(Network::Testnet, KeyApplication::Nested, true),
            KeyVersion(VERSION_MAGIC_UPRV)
        );
        assert_eq!(
            DefaultResolver::resolve(Network::Testnet, KeyApplication::NestedMultisig, true),
            KeyVersion(VERSION_MAGIC_UPRV_MULTISIG)
        );
        assert_eq!(
            DefaultResolver::resolve(Network::Testnet, KeyApplication::Nested, false),
            KeyVersion(VERSION_MAGIC_UPUB)
        );
        assert_eq!(
            DefaultResolver::resolve(Network::Testnet, KeyApplication::NestedMultisig, false),
            KeyVersion(VERSION_MAGIC_UPUB_MULTISIG)
        );

        assert_eq!(
            DefaultResolver::resolve(Network::Testnet, KeyApplication::SegWit, true),
            KeyVersion(VERSION_MAGIC_VPRV)
        );
        assert_eq!(
            DefaultResolver::resolve(Network::Testnet, KeyApplication::SegWitMultisig, true),
            KeyVersion(VERSION_MAGIC_VPRV_MULTISIG)
        );
        assert_eq!(
            DefaultResolver::resolve(Network::Testnet, KeyApplication::SegWit, false),
            KeyVersion(VERSION_MAGIC_VPUB)
        );
        assert_eq!(
            DefaultResolver::resolve(Network::Testnet, KeyApplication::SegWitMultisig, false),
            KeyVersion(VERSION_MAGIC_VPUB_MULTISIG)
        );

        assert_eq!(
            DefaultResolver::resolve(Network::Bitcoin, KeyApplication::Hashed, true),
            KeyVersion(VERSION_MAGIC_XPRV)
        );
        assert_eq!(
            DefaultResolver::resolve(Network::Bitcoin, KeyApplication::Hashed, false),
            KeyVersion(VERSION_MAGIC_XPUB)
        );

        assert_eq!(
            DefaultResolver::resolve(Network::Bitcoin, KeyApplication::Nested, true),
            KeyVersion(VERSION_MAGIC_YPRV)
        );
        assert_eq!(
            DefaultResolver::resolve(Network::Bitcoin, KeyApplication::NestedMultisig, true),
            KeyVersion(VERSION_MAGIC_YPRV_MULTISIG)
        );
        assert_eq!(
            DefaultResolver::resolve(Network::Bitcoin, KeyApplication::Nested, false),
            KeyVersion(VERSION_MAGIC_YPUB)
        );
        assert_eq!(
            DefaultResolver::resolve(Network::Bitcoin, KeyApplication::NestedMultisig, false),
            KeyVersion(VERSION_MAGIC_YPUB_MULTISIG)
        );

        assert_eq!(
            DefaultResolver::resolve(Network::Bitcoin, KeyApplication::SegWit, true),
            KeyVersion(VERSION_MAGIC_ZPRV)
        );
        assert_eq!(
            DefaultResolver::resolve(Network::Bitcoin, KeyApplication::SegWitMultisig, true),
            KeyVersion(VERSION_MAGIC_ZPRV_MULTISIG)
        );
        assert_eq!(
            DefaultResolver::resolve(Network::Bitcoin, KeyApplication::SegWit, false),
            KeyVersion(VERSION_MAGIC_ZPUB)
        );
        assert_eq!(
            DefaultResolver::resolve(Network::Bitcoin, KeyApplication::SegWitMultisig, false),
            KeyVersion(VERSION_MAGIC_ZPUB_MULTISIG)
        );
    }

    #[test]
    fn default_resolver_is_pub() {
        assert!(!DefaultResolver::is_pub(&KeyVersion(VERSION_MAGIC_TPRV)).unwrap());
        assert!(DefaultResolver::is_pub(&KeyVersion(VERSION_MAGIC_TPUB)).unwrap());

        assert!(!DefaultResolver::is_pub(&KeyVersion(VERSION_MAGIC_UPRV)).unwrap());
        assert!(!DefaultResolver::is_pub(&KeyVersion(VERSION_MAGIC_UPRV_MULTISIG)).unwrap());
        assert!(DefaultResolver::is_pub(&KeyVersion(VERSION_MAGIC_UPUB)).unwrap());
        assert!(DefaultResolver::is_pub(&KeyVersion(VERSION_MAGIC_UPUB_MULTISIG)).unwrap());

        assert!(!DefaultResolver::is_pub(&KeyVersion(VERSION_MAGIC_VPRV)).unwrap());
        assert!(!DefaultResolver::is_pub(&KeyVersion(VERSION_MAGIC_VPRV_MULTISIG)).unwrap());
        assert!(DefaultResolver::is_pub(&KeyVersion(VERSION_MAGIC_VPUB)).unwrap());
        assert!(DefaultResolver::is_pub(&KeyVersion(VERSION_MAGIC_VPUB_MULTISIG)).unwrap());

        assert!(!DefaultResolver::is_pub(&KeyVersion(VERSION_MAGIC_XPRV)).unwrap());
        assert!(DefaultResolver::is_pub(&KeyVersion(VERSION_MAGIC_XPUB)).unwrap());

        assert!(!DefaultResolver::is_pub(&KeyVersion(VERSION_MAGIC_YPRV)).unwrap());
        assert!(!DefaultResolver::is_pub(&KeyVersion(VERSION_MAGIC_YPRV_MULTISIG)).unwrap());
        assert!(DefaultResolver::is_pub(&KeyVersion(VERSION_MAGIC_YPUB)).unwrap());
        assert!(DefaultResolver::is_pub(&KeyVersion(VERSION_MAGIC_YPUB_MULTISIG)).unwrap());

        assert!(!DefaultResolver::is_pub(&KeyVersion(VERSION_MAGIC_ZPRV)).unwrap());
        assert!(!DefaultResolver::is_pub(&KeyVersion(VERSION_MAGIC_ZPRV_MULTISIG)).unwrap());
        assert!(DefaultResolver::is_pub(&KeyVersion(VERSION_MAGIC_ZPUB)).unwrap());
        assert!(DefaultResolver::is_pub(&KeyVersion(VERSION_MAGIC_ZPUB_MULTISIG)).unwrap());

        assert!(DefaultResolver::is_pub(&KeyVersion([0, 0, 0, 0])).is_none());
    }

    #[test]
    fn default_resolver_is_prv() {
        assert!(DefaultResolver::is_prv(&KeyVersion(VERSION_MAGIC_TPRV)).unwrap());
        assert!(!DefaultResolver::is_prv(&KeyVersion(VERSION_MAGIC_TPUB)).unwrap());

        assert!(DefaultResolver::is_prv(&KeyVersion(VERSION_MAGIC_UPRV)).unwrap());
        assert!(DefaultResolver::is_prv(&KeyVersion(VERSION_MAGIC_UPRV_MULTISIG)).unwrap());
        assert!(!DefaultResolver::is_prv(&KeyVersion(VERSION_MAGIC_UPUB)).unwrap());
        assert!(!DefaultResolver::is_prv(&KeyVersion(VERSION_MAGIC_UPUB_MULTISIG)).unwrap());

        assert!(DefaultResolver::is_prv(&KeyVersion(VERSION_MAGIC_VPRV)).unwrap());
        assert!(DefaultResolver::is_prv(&KeyVersion(VERSION_MAGIC_VPRV_MULTISIG)).unwrap());
        assert!(!DefaultResolver::is_prv(&KeyVersion(VERSION_MAGIC_VPUB)).unwrap());
        assert!(!DefaultResolver::is_prv(&KeyVersion(VERSION_MAGIC_VPUB_MULTISIG)).unwrap());

        assert!(DefaultResolver::is_prv(&KeyVersion(VERSION_MAGIC_XPRV)).unwrap());
        assert!(!DefaultResolver::is_prv(&KeyVersion(VERSION_MAGIC_XPUB)).unwrap());

        assert!(DefaultResolver::is_prv(&KeyVersion(VERSION_MAGIC_YPRV)).unwrap());
        assert!(DefaultResolver::is_prv(&KeyVersion(VERSION_MAGIC_YPRV_MULTISIG)).unwrap());
        assert!(!DefaultResolver::is_prv(&KeyVersion(VERSION_MAGIC_YPUB)).unwrap());
        assert!(!DefaultResolver::is_prv(&KeyVersion(VERSION_MAGIC_YPUB_MULTISIG)).unwrap());

        assert!(DefaultResolver::is_prv(&KeyVersion(VERSION_MAGIC_ZPRV)).unwrap());
        assert!(DefaultResolver::is_prv(&KeyVersion(VERSION_MAGIC_ZPRV_MULTISIG)).unwrap());
        assert!(!DefaultResolver::is_prv(&KeyVersion(VERSION_MAGIC_ZPUB)).unwrap());
        assert!(!DefaultResolver::is_prv(&KeyVersion(VERSION_MAGIC_ZPUB_MULTISIG)).unwrap());

        assert!(DefaultResolver::is_prv(&KeyVersion([0, 0, 0, 0])).is_none());
    }

    #[test]
    fn default_resolver_network() {
        assert_eq!(
            DefaultResolver::network(&KeyVersion(VERSION_MAGIC_TPRV)),
            Some(Network::Testnet)
        );
        assert_eq!(
            DefaultResolver::network(&KeyVersion(VERSION_MAGIC_TPUB)),
            Some(Network::Testnet)
        );

        assert_eq!(
            DefaultResolver::network(&KeyVersion(VERSION_MAGIC_UPRV)),
            Some(Network::Testnet)
        );
        assert_eq!(
            DefaultResolver::network(&KeyVersion(VERSION_MAGIC_UPRV_MULTISIG)),
            Some(Network::Testnet)
        );
        assert_eq!(
            DefaultResolver::network(&KeyVersion(VERSION_MAGIC_UPUB)),
            Some(Network::Testnet)
        );
        assert_eq!(
            DefaultResolver::network(&KeyVersion(VERSION_MAGIC_UPUB_MULTISIG)),
            Some(Network::Testnet)
        );

        assert_eq!(
            DefaultResolver::network(&KeyVersion(VERSION_MAGIC_VPRV)),
            Some(Network::Testnet)
        );
        assert_eq!(
            DefaultResolver::network(&KeyVersion(VERSION_MAGIC_VPRV_MULTISIG)),
            Some(Network::Testnet)
        );
        assert_eq!(
            DefaultResolver::network(&KeyVersion(VERSION_MAGIC_VPUB)),
            Some(Network::Testnet)
        );
        assert_eq!(
            DefaultResolver::network(&KeyVersion(VERSION_MAGIC_VPUB_MULTISIG)),
            Some(Network::Testnet)
        );

        assert_eq!(
            DefaultResolver::network(&KeyVersion(VERSION_MAGIC_XPRV)),
            Some(Network::Bitcoin)
        );
        assert_eq!(
            DefaultResolver::network(&KeyVersion(VERSION_MAGIC_XPUB)),
            Some(Network::Bitcoin)
        );

        assert_eq!(
            DefaultResolver::network(&KeyVersion(VERSION_MAGIC_YPRV)),
            Some(Network::Bitcoin)
        );
        assert_eq!(
            DefaultResolver::network(&KeyVersion(VERSION_MAGIC_YPRV_MULTISIG)),
            Some(Network::Bitcoin)
        );
        assert_eq!(
            DefaultResolver::network(&KeyVersion(VERSION_MAGIC_YPUB)),
            Some(Network::Bitcoin)
        );
        assert_eq!(
            DefaultResolver::network(&KeyVersion(VERSION_MAGIC_YPUB_MULTISIG)),
            Some(Network::Bitcoin)
        );

        assert_eq!(
            DefaultResolver::network(&KeyVersion(VERSION_MAGIC_ZPRV)),
            Some(Network::Bitcoin)
        );
        assert_eq!(
            DefaultResolver::network(&KeyVersion(VERSION_MAGIC_ZPRV_MULTISIG)),
            Some(Network::Bitcoin)
        );
        assert_eq!(
            DefaultResolver::network(&KeyVersion(VERSION_MAGIC_ZPUB)),
            Some(Network::Bitcoin)
        );
        assert_eq!(
            DefaultResolver::network(&KeyVersion(VERSION_MAGIC_ZPUB_MULTISIG)),
            Some(Network::Bitcoin)
        );

        assert!(DefaultResolver::network(&KeyVersion([0, 0, 0, 0])).is_none());
    }

    #[test]
    fn default_resolver_application() {
        assert_eq!(
            DefaultResolver::application(&KeyVersion(VERSION_MAGIC_TPRV)),
            None
        );
        assert_eq!(
            DefaultResolver::application(&KeyVersion(VERSION_MAGIC_TPUB)),
            None
        );

        assert_eq!(
            DefaultResolver::application(&KeyVersion(VERSION_MAGIC_UPRV)),
            Some(KeyApplication::Nested)
        );
        assert_eq!(
            DefaultResolver::application(&KeyVersion(VERSION_MAGIC_UPRV_MULTISIG)),
            Some(KeyApplication::NestedMultisig)
        );
        assert_eq!(
            DefaultResolver::application(&KeyVersion(VERSION_MAGIC_UPUB)),
            Some(KeyApplication::Nested)
        );
        assert_eq!(
            DefaultResolver::application(&KeyVersion(VERSION_MAGIC_UPUB_MULTISIG)),
            Some(KeyApplication::NestedMultisig)
        );

        assert_eq!(
            DefaultResolver::application(&KeyVersion(VERSION_MAGIC_VPRV)),
            Some(KeyApplication::SegWit)
        );
        assert_eq!(
            DefaultResolver::application(&KeyVersion(VERSION_MAGIC_VPRV_MULTISIG)),
            Some(KeyApplication::SegWitMultisig)
        );
        assert_eq!(
            DefaultResolver::application(&KeyVersion(VERSION_MAGIC_VPUB)),
            Some(KeyApplication::SegWit)
        );
        assert_eq!(
            DefaultResolver::application(&KeyVersion(VERSION_MAGIC_VPUB_MULTISIG)),
            Some(KeyApplication::SegWitMultisig)
        );

        assert_eq!(
            DefaultResolver::application(&KeyVersion(VERSION_MAGIC_XPRV)),
            None
        );
        assert_eq!(
            DefaultResolver::application(&KeyVersion(VERSION_MAGIC_XPUB)),
            None
        );

        assert_eq!(
            DefaultResolver::application(&KeyVersion(VERSION_MAGIC_YPRV)),
            Some(KeyApplication::Nested)
        );
        assert_eq!(
            DefaultResolver::application(&KeyVersion(VERSION_MAGIC_YPRV_MULTISIG)),
            Some(KeyApplication::NestedMultisig)
        );
        assert_eq!(
            DefaultResolver::application(&KeyVersion(VERSION_MAGIC_YPUB)),
            Some(KeyApplication::Nested)
        );
        assert_eq!(
            DefaultResolver::application(&KeyVersion(VERSION_MAGIC_YPUB_MULTISIG)),
            Some(KeyApplication::NestedMultisig)
        );

        assert_eq!(
            DefaultResolver::application(&KeyVersion(VERSION_MAGIC_ZPRV)),
            Some(KeyApplication::SegWit)
        );
        assert_eq!(
            DefaultResolver::application(&KeyVersion(VERSION_MAGIC_ZPRV_MULTISIG)),
            Some(KeyApplication::SegWitMultisig)
        );
        assert_eq!(
            DefaultResolver::application(&KeyVersion(VERSION_MAGIC_ZPUB)),
            Some(KeyApplication::SegWit)
        );
        assert_eq!(
            DefaultResolver::application(&KeyVersion(VERSION_MAGIC_ZPUB_MULTISIG)),
            Some(KeyApplication::SegWitMultisig)
        );

        assert!(DefaultResolver::application(&KeyVersion([0, 0, 0, 0])).is_none());
    }

    #[test]
    fn default_resolver_derivation_path() {
        let account = Some(ChildNumber::Hardened { index: 100 });

        assert_eq!(
            DefaultResolver::derivation_path(&KeyVersion(VERSION_MAGIC_TPRV), account),
            None
        );
        assert_eq!(
            DefaultResolver::derivation_path(&KeyVersion(VERSION_MAGIC_TPUB), account),
            None
        );

        assert_eq!(
            DefaultResolver::derivation_path(&KeyVersion(VERSION_MAGIC_UPRV), account)
                .unwrap()
                .to_string(),
            "m/49'/1'/100'"
        );
        assert_eq!(
            DefaultResolver::derivation_path(&KeyVersion(VERSION_MAGIC_UPRV_MULTISIG), account)
                .unwrap()
                .to_string(),
            "m/48'/1'/100'/1'"
        );
        assert_eq!(
            DefaultResolver::derivation_path(&KeyVersion(VERSION_MAGIC_UPUB), account)
                .unwrap()
                .to_string(),
            "m/49'/1'/100'"
        );
        assert_eq!(
            DefaultResolver::derivation_path(&KeyVersion(VERSION_MAGIC_UPUB_MULTISIG), account)
                .unwrap()
                .to_string(),
            "m/48'/1'/100'/1'"
        );

        assert_eq!(
            DefaultResolver::derivation_path(&KeyVersion(VERSION_MAGIC_VPRV), account)
                .unwrap()
                .to_string(),
            "m/84'/1'/100'"
        );
        assert_eq!(
            DefaultResolver::derivation_path(&KeyVersion(VERSION_MAGIC_VPRV_MULTISIG), account)
                .unwrap()
                .to_string(),
            "m/48'/1'/100'/2'"
        );
        assert_eq!(
            DefaultResolver::derivation_path(&KeyVersion(VERSION_MAGIC_VPUB), account)
                .unwrap()
                .to_string(),
            "m/84'/1'/100'"
        );
        assert_eq!(
            DefaultResolver::derivation_path(&KeyVersion(VERSION_MAGIC_VPUB_MULTISIG), account)
                .unwrap()
                .to_string(),
            "m/48'/1'/100'/2'"
        );

        assert_eq!(
            DefaultResolver::derivation_path(&KeyVersion(VERSION_MAGIC_XPRV), account),
            None
        );
        assert_eq!(
            DefaultResolver::derivation_path(&KeyVersion(VERSION_MAGIC_XPUB), account),
            None
        );

        assert_eq!(
            DefaultResolver::derivation_path(&KeyVersion(VERSION_MAGIC_YPRV), account)
                .unwrap()
                .to_string(),
            "m/49'/0'/100'"
        );
        assert_eq!(
            DefaultResolver::derivation_path(&KeyVersion(VERSION_MAGIC_YPRV_MULTISIG), account)
                .unwrap()
                .to_string(),
            "m/48'/0'/100'/1'"
        );
        assert_eq!(
            DefaultResolver::derivation_path(&KeyVersion(VERSION_MAGIC_YPUB), account)
                .unwrap()
                .to_string(),
            "m/49'/0'/100'"
        );
        assert_eq!(
            DefaultResolver::derivation_path(&KeyVersion(VERSION_MAGIC_YPUB_MULTISIG), account)
                .unwrap()
                .to_string(),
            "m/48'/0'/100'/1'"
        );

        assert_eq!(
            DefaultResolver::derivation_path(&KeyVersion(VERSION_MAGIC_ZPRV), account)
                .unwrap()
                .to_string(),
            "m/84'/0'/100'"
        );
        assert_eq!(
            DefaultResolver::derivation_path(&KeyVersion(VERSION_MAGIC_ZPRV_MULTISIG), account)
                .unwrap()
                .to_string(),
            "m/48'/0'/100'/2'"
        );
        assert_eq!(
            DefaultResolver::derivation_path(&KeyVersion(VERSION_MAGIC_ZPUB), account)
                .unwrap()
                .to_string(),
            "m/84'/0'/100'"
        );
        assert_eq!(
            DefaultResolver::derivation_path(&KeyVersion(VERSION_MAGIC_ZPUB_MULTISIG), account)
                .unwrap()
                .to_string(),
            "m/48'/0'/100'/2'"
        );

        assert!(DefaultResolver::derivation_path(&KeyVersion([0, 0, 0, 0]), account).is_none());
    }

    #[test]
    fn default_resolver_make_pub() {
        assert_eq!(
            DefaultResolver::make_pub(&KeyVersion(VERSION_MAGIC_TPRV)),
            Some(KeyVersion(VERSION_MAGIC_TPUB))
        );
        assert_eq!(
            DefaultResolver::make_pub(&KeyVersion(VERSION_MAGIC_TPUB)),
            Some(KeyVersion(VERSION_MAGIC_TPUB))
        );

        assert_eq!(
            DefaultResolver::make_pub(&KeyVersion(VERSION_MAGIC_UPRV)),
            Some(KeyVersion(VERSION_MAGIC_UPUB))
        );
        assert_eq!(
            DefaultResolver::make_pub(&KeyVersion(VERSION_MAGIC_UPRV_MULTISIG)),
            Some(KeyVersion(VERSION_MAGIC_UPUB_MULTISIG))
        );
        assert_eq!(
            DefaultResolver::make_pub(&KeyVersion(VERSION_MAGIC_UPUB)),
            Some(KeyVersion(VERSION_MAGIC_UPUB))
        );
        assert_eq!(
            DefaultResolver::make_pub(&KeyVersion(VERSION_MAGIC_UPUB_MULTISIG)),
            Some(KeyVersion(VERSION_MAGIC_UPUB_MULTISIG))
        );

        assert_eq!(
            DefaultResolver::make_pub(&KeyVersion(VERSION_MAGIC_VPRV)),
            Some(KeyVersion(VERSION_MAGIC_VPUB))
        );
        assert_eq!(
            DefaultResolver::make_pub(&KeyVersion(VERSION_MAGIC_VPRV_MULTISIG)),
            Some(KeyVersion(VERSION_MAGIC_VPUB_MULTISIG))
        );
        assert_eq!(
            DefaultResolver::make_pub(&KeyVersion(VERSION_MAGIC_VPUB)),
            Some(KeyVersion(VERSION_MAGIC_VPUB))
        );
        assert_eq!(
            DefaultResolver::make_pub(&KeyVersion(VERSION_MAGIC_VPUB_MULTISIG)),
            Some(KeyVersion(VERSION_MAGIC_VPUB_MULTISIG))
        );

        assert_eq!(
            DefaultResolver::make_pub(&KeyVersion(VERSION_MAGIC_XPRV)),
            Some(KeyVersion(VERSION_MAGIC_XPUB))
        );
        assert_eq!(
            DefaultResolver::make_pub(&KeyVersion(VERSION_MAGIC_XPUB)),
            Some(KeyVersion(VERSION_MAGIC_XPUB))
        );

        assert_eq!(
            DefaultResolver::make_pub(&KeyVersion(VERSION_MAGIC_YPRV)),
            Some(KeyVersion(VERSION_MAGIC_YPUB))
        );
        assert_eq!(
            DefaultResolver::make_pub(&KeyVersion(VERSION_MAGIC_YPRV_MULTISIG)),
            Some(KeyVersion(VERSION_MAGIC_YPUB_MULTISIG))
        );
        assert_eq!(
            DefaultResolver::make_pub(&KeyVersion(VERSION_MAGIC_YPUB)),
            Some(KeyVersion(VERSION_MAGIC_YPUB))
        );
        assert_eq!(
            DefaultResolver::make_pub(&KeyVersion(VERSION_MAGIC_YPUB_MULTISIG)),
            Some(KeyVersion(VERSION_MAGIC_YPUB_MULTISIG))
        );

        assert_eq!(
            DefaultResolver::make_pub(&KeyVersion(VERSION_MAGIC_ZPRV)),
            Some(KeyVersion(VERSION_MAGIC_ZPUB))
        );
        assert_eq!(
            DefaultResolver::make_pub(&KeyVersion(VERSION_MAGIC_ZPRV_MULTISIG)),
            Some(KeyVersion(VERSION_MAGIC_ZPUB_MULTISIG))
        );
        assert_eq!(
            DefaultResolver::make_pub(&KeyVersion(VERSION_MAGIC_ZPUB)),
            Some(KeyVersion(VERSION_MAGIC_ZPUB))
        );
        assert_eq!(
            DefaultResolver::make_pub(&KeyVersion(VERSION_MAGIC_ZPUB_MULTISIG)),
            Some(KeyVersion(VERSION_MAGIC_ZPUB_MULTISIG))
        );

        assert!(DefaultResolver::make_pub(&KeyVersion([0, 0, 0, 0])).is_none());
    }

    #[test]
    fn default_resolver_make_prv() {
        assert_eq!(
            DefaultResolver::make_prv(&KeyVersion(VERSION_MAGIC_TPRV)),
            Some(KeyVersion(VERSION_MAGIC_TPRV))
        );
        assert_eq!(
            DefaultResolver::make_prv(&KeyVersion(VERSION_MAGIC_TPUB)),
            Some(KeyVersion(VERSION_MAGIC_TPRV))
        );

        assert_eq!(
            DefaultResolver::make_prv(&KeyVersion(VERSION_MAGIC_UPRV)),
            Some(KeyVersion(VERSION_MAGIC_UPRV))
        );
        assert_eq!(
            DefaultResolver::make_prv(&KeyVersion(VERSION_MAGIC_UPRV_MULTISIG)),
            Some(KeyVersion(VERSION_MAGIC_UPRV_MULTISIG))
        );
        assert_eq!(
            DefaultResolver::make_prv(&KeyVersion(VERSION_MAGIC_UPUB)),
            Some(KeyVersion(VERSION_MAGIC_UPRV))
        );
        assert_eq!(
            DefaultResolver::make_prv(&KeyVersion(VERSION_MAGIC_UPUB_MULTISIG)),
            Some(KeyVersion(VERSION_MAGIC_UPRV_MULTISIG))
        );

        assert_eq!(
            DefaultResolver::make_prv(&KeyVersion(VERSION_MAGIC_VPRV)),
            Some(KeyVersion(VERSION_MAGIC_VPRV))
        );
        assert_eq!(
            DefaultResolver::make_prv(&KeyVersion(VERSION_MAGIC_VPRV_MULTISIG)),
            Some(KeyVersion(VERSION_MAGIC_VPRV_MULTISIG))
        );
        assert_eq!(
            DefaultResolver::make_prv(&KeyVersion(VERSION_MAGIC_VPUB)),
            Some(KeyVersion(VERSION_MAGIC_VPRV))
        );
        assert_eq!(
            DefaultResolver::make_prv(&KeyVersion(VERSION_MAGIC_VPUB_MULTISIG)),
            Some(KeyVersion(VERSION_MAGIC_VPRV_MULTISIG))
        );

        assert_eq!(
            DefaultResolver::make_prv(&KeyVersion(VERSION_MAGIC_XPRV)),
            Some(KeyVersion(VERSION_MAGIC_XPRV))
        );
        assert_eq!(
            DefaultResolver::make_prv(&KeyVersion(VERSION_MAGIC_XPUB)),
            Some(KeyVersion(VERSION_MAGIC_XPRV))
        );

        assert_eq!(
            DefaultResolver::make_prv(&KeyVersion(VERSION_MAGIC_YPRV)),
            Some(KeyVersion(VERSION_MAGIC_YPRV))
        );
        assert_eq!(
            DefaultResolver::make_prv(&KeyVersion(VERSION_MAGIC_YPRV_MULTISIG)),
            Some(KeyVersion(VERSION_MAGIC_YPRV_MULTISIG))
        );
        assert_eq!(
            DefaultResolver::make_prv(&KeyVersion(VERSION_MAGIC_YPUB)),
            Some(KeyVersion(VERSION_MAGIC_YPRV))
        );
        assert_eq!(
            DefaultResolver::make_prv(&KeyVersion(VERSION_MAGIC_YPUB_MULTISIG)),
            Some(KeyVersion(VERSION_MAGIC_YPRV_MULTISIG))
        );

        assert_eq!(
            DefaultResolver::make_prv(&KeyVersion(VERSION_MAGIC_ZPRV)),
            Some(KeyVersion(VERSION_MAGIC_ZPRV))
        );
        assert_eq!(
            DefaultResolver::make_prv(&KeyVersion(VERSION_MAGIC_ZPRV_MULTISIG)),
            Some(KeyVersion(VERSION_MAGIC_ZPRV_MULTISIG))
        );
        assert_eq!(
            DefaultResolver::make_prv(&KeyVersion(VERSION_MAGIC_ZPUB)),
            Some(KeyVersion(VERSION_MAGIC_ZPRV))
        );
        assert_eq!(
            DefaultResolver::make_prv(&KeyVersion(VERSION_MAGIC_ZPUB_MULTISIG)),
            Some(KeyVersion(VERSION_MAGIC_ZPRV_MULTISIG))
        );

        assert!(DefaultResolver::make_prv(&KeyVersion([0, 0, 0, 0])).is_none());
    }

    #[test]
    fn xpub_from_slip132_str() {
        // Mainnet
        let xpub_str = "xpub6BosfCnifzxcJJ1wYuntGJfF2zPJkDeG9ELNHcKNjezuea4tumswN9sH1psMdSVqCMoJC21Bv8usSeqSP4Sp1tLzW7aY59fGn9GCYzx5UTo";
        let xpub = Xpub::from_str(xpub_str).unwrap();
        let ypub_str = "ypub6We8xsTdpgW69bD4PGaWUPkkCxXkgqdm4Lrb51DG7fNnhft8AS3VzDXR32pwdM9kbzv6wVbkNoGRKwT16krpp82bNTGxf4Um3sKqwYoGn8q";
        let ypub_multi = "Ypub6hYE67C5Pe4TaANSKw3VJU6Yvka1uCKMNcWFzGUoVSDCKrT2vqRn5LPLqjnRBnNeqTz5p5bsG1evT74mPz1mxc9GCvPN4TwkwbbiXTy4WMA";
        let zpub_str = "zpub6qUQGY8YyN3ZztQBDdN8gUrFNvgCdTdFyTNorQ79VfkfkmhMR6D4cHBZ4EnXdFog1e2ugyCJqTcyDE4ZpTGqcMiCEnyPEyJFKbPVL9knhKU";
        let zpub_multi = "Zpub72NVPmrzYKbwRTZZAHq7WZC46iiTqpJrHj2UmfNgsSb5NxGGBVbLhQ3Urwk1Bh2aF76tZZCRig1ULPgL7gRnkqps5G5neNmFDKfMv51dh4F";
        assert_eq!(Xpub::from_slip132_str(xpub_str), Ok(xpub));
        assert_eq!(Xpub::from_slip132_str(ypub_str), Ok(xpub));
        assert_eq!(Xpub::from_slip132_str(ypub_multi), Ok(xpub));
        assert_eq!(Xpub::from_slip132_str(zpub_str), Ok(xpub));
        assert_eq!(Xpub::from_slip132_str(zpub_multi), Ok(xpub));

        // Testnet
        let tpub_str = "tpubDCBWBScQPGv4a6Co16myUDzcN7Uxjc9KgrvfeANX5ZkoPrjbyzj2WbY7Frx99wT4zGLCobX4TEjv8qL3mvJ3uKoHZiKqkgKWN6rcK3NAdLv";
        let tpub = Xpub::from_str(tpub_str).unwrap();
        let upub_str = "upub5DK5kCmyDxLAkQSb3qS1e3NjX5wxvMfmPtmhwRdibdsGVGdD9oPFVxtrxCzbdiY4ySSswbDWY9rDnnzkDyCmdBJBu6VGKRCoxy5GPFTTwv5";
        let upub_multi = "Upub5QDAsSWQnutYAybxzVtzU7iYEszE8iMMiARNrguFyQhg7TC7vCmXb5knkux5C9kyCuWrpBDdRNEiuxcWXCMimfQrjZbfipforhM8yFdtHZV";
        let vpub_str = "vpub5Y9M3sStNdsebhdhtCDdr8UEh46QryfGK1HvipXbyeF9YNSSQTYp82YzyQxBddBzP5Zgh4p4zpCmg5cJwfcnRQynmSBguL2JEh8umtXSXHN";
        let vpub_multi = "Vpub5j3SB7BKwbS22Go5prgcgCp3Qr8g5LLrdGwbe5o9MR5ZAZ1MArw6D9Qvn7ufC4QtcYdfZepBt2bGoFE5EtmjZu6TbuJ6JjVJ8RQnMkMTT7U";
        assert_eq!(Xpub::from_slip132_str(tpub_str), Ok(tpub));
        assert_eq!(Xpub::from_slip132_str(upub_str), Ok(tpub));
        assert_eq!(Xpub::from_slip132_str(upub_multi), Ok(tpub));
        assert_eq!(Xpub::from_slip132_str(vpub_str), Ok(tpub));
        assert_eq!(Xpub::from_slip132_str(vpub_multi), Ok(tpub));
    }

    #[test]
    fn xprv_from_slip132_str() {
        // Mainnet
        let xprv_str = "xprv9xpXFhFpqdQK5owUStFsuAiWUxYpLkvQn1QmVDumBKTvmmjkNEZgpMYoAaAftt3JVeDhRkvyLvrKathDToUMdz2FqRF7JNavF7uboJWArrw";
        let xprv = Xpriv::from_str(xprv_str).unwrap();
        let yprv_str = "yprvAHenZMvjzJwnw78bHF3W7Fp1evhGHNuuh7vzGcoeZKqopsYyctjFSRCwBn8FtnhDuHLWBEXXobCsUBJnBVtNSDhrhkwXtHQQWqyFBpXETuS";
        let yprv_multi = "YprvAUYsgbfBZGWAMgHyDuWUwL9pNijXVjbW1PafBt5Bw6gDT47tPJ7XXY4rzV5jTDv88kQV3pXegobNbLvYUj3KahpXYE3wHgsQQaF7mkmDXua";
        let zprv_str = "zprvAcV3s2bf8zVGnQKi7bq8KLuWptqiDzuQcETD41hXwLDgsyNCsYtp4Us5Cz5qthM9JvTJvi86GFZRMTvLuCJPETPTa6dxUCDtna2taUzNeUa";
        let zprv_multi = "ZprvAoP8zGL6hx3eCyV64GJ79RFKYgsySMazvW6syGy5K746W9w7dxH69bj11h3KT8a3YPXHoJ8D9TwvUdY7CRTLNwW8QZkMsbgtgJJmANdRWza";
        assert_eq!(Xpriv::from_slip132_str(xprv_str), Ok(xprv));
        assert_eq!(Xpriv::from_slip132_str(yprv_str), Ok(xprv));
        assert_eq!(Xpriv::from_slip132_str(yprv_multi), Ok(xprv));
        assert_eq!(Xpriv::from_slip132_str(zprv_str), Ok(xprv));
        assert_eq!(Xpriv::from_slip132_str(zprv_multi), Ok(xprv));

        // Testnet
        let tprv_str = "tprv8fVU32aAEuEPgdB17T7P4pLVo5y2aGxR7ZKtMeLDfHxQZNUqMbuSL6vF5kLKuFRcs5kURrYjWHS83kExb1pJT3HrN4TQxjJyADf2F32kmMf";
        let tprv = Xpriv::from_str(tprv_str).unwrap();
        let uprv_str = "uprv8zKjLhF5PamsXvN7wou1GuRzy47UWtwv2fr793E73JLHcUJ4cG4zxAaP6xHuuA5YGisHBL9Hxwnfw2rXJiEKFGyTEQ9qYe8TRwifdcMUKTP";
        let uprv_multi = "Uprv9BDpTvyWxYLExVXVtUMz6ymogr9jjFdWLwVn4JVeR5AhEeryNfTH3HSJufFPTbJSWBwG3v9QrABB4CUHbwPGPm684sGEx3bTKfzYDSPHHCV";
        let vprv_str = "vprv9K9zeMuzYGKMPDZEnAgdUzXW92FvTWwQwnNKvS7zRJiAfa7HrvEZaEEX8AFVu4jTgMz5vojrRc9DpKU62QeL3Wf46jrG8YwwhfnK26J1Pi6";
        let vprv_multi = "Vprv1CMQ2h95oDkM8omHwD22Go9vqpcjv19x3yLpMZkqw9HAL4kaYU7W2eo4c1HqwNPSVN3wBuqrw5HUiA8z3zHz7cb2QFRfWnUkvYDCHhvLxCW";
        assert_eq!(Xpriv::from_slip132_str(tprv_str), Ok(tprv));
        assert_eq!(Xpriv::from_slip132_str(uprv_str), Ok(tprv));
        assert_eq!(Xpriv::from_slip132_str(uprv_multi), Ok(tprv));
        assert_eq!(Xpriv::from_slip132_str(vprv_str), Ok(tprv));
        assert_eq!(Xpriv::from_slip132_str(vprv_multi), Ok(tprv));
    }

    #[test]
    fn xpub_to_slip132_string() {
        let xpub_str = "xpub6BosfCnifzxcJJ1wYuntGJfF2zPJkDeG9ELNHcKNjezuea4tumswN9sH1psMdSVqCMoJC21Bv8usSeqSP4Sp1tLzW7aY59fGn9GCYzx5UTo";
        let xpub = Xpub::from_str(xpub_str).unwrap();

        // Mainnet
        assert_eq!(
            xpub.to_slip132_string(KeyApplication::Hashed, Network::Bitcoin),
            xpub_str
        );
        assert_eq!(
            xpub.to_slip132_string(KeyApplication::Nested, Network::Bitcoin),
            "ypub6We8xsTdpgW69bD4PGaWUPkkCxXkgqdm4Lrb51DG7fNnhft8AS3VzDXR32pwdM9kbzv6wVbkNoGRKwT16krpp82bNTGxf4Um3sKqwYoGn8q"
        );
        assert_eq!(
            xpub.to_slip132_string(KeyApplication::NestedMultisig, Network::Bitcoin),
            "Ypub6hYE67C5Pe4TaANSKw3VJU6Yvka1uCKMNcWFzGUoVSDCKrT2vqRn5LPLqjnRBnNeqTz5p5bsG1evT74mPz1mxc9GCvPN4TwkwbbiXTy4WMA"
        );
        assert_eq!(
            xpub.to_slip132_string(KeyApplication::SegWit, Network::Bitcoin),
            "zpub6qUQGY8YyN3ZztQBDdN8gUrFNvgCdTdFyTNorQ79VfkfkmhMR6D4cHBZ4EnXdFog1e2ugyCJqTcyDE4ZpTGqcMiCEnyPEyJFKbPVL9knhKU"
        );
        assert_eq!(
            xpub.to_slip132_string(KeyApplication::SegWitMultisig, Network::Bitcoin),
            "Zpub72NVPmrzYKbwRTZZAHq7WZC46iiTqpJrHj2UmfNgsSb5NxGGBVbLhQ3Urwk1Bh2aF76tZZCRig1ULPgL7gRnkqps5G5neNmFDKfMv51dh4F"
        );

        // Testnet
        assert_eq!(
            xpub.to_slip132_string(KeyApplication::Hashed, Network::Testnet),
            "tpubDCBWBScQPGv4a6Co16myUDzcN7Uxjc9KgrvfeANX5ZkoPrjbyzj2WbY7Frx99wT4zGLCobX4TEjv8qL3mvJ3uKoHZiKqkgKWN6rcK3NAdLv"
        );
        assert_eq!(
            xpub.to_slip132_string(KeyApplication::Nested, Network::Testnet),
            "upub5DK5kCmyDxLAkQSb3qS1e3NjX5wxvMfmPtmhwRdibdsGVGdD9oPFVxtrxCzbdiY4ySSswbDWY9rDnnzkDyCmdBJBu6VGKRCoxy5GPFTTwv5"
        );
        assert_eq!(
            xpub.to_slip132_string(KeyApplication::NestedMultisig, Network::Testnet),
            "Upub5QDAsSWQnutYAybxzVtzU7iYEszE8iMMiARNrguFyQhg7TC7vCmXb5knkux5C9kyCuWrpBDdRNEiuxcWXCMimfQrjZbfipforhM8yFdtHZV"
        );
        assert_eq!(
            xpub.to_slip132_string(KeyApplication::SegWit, Network::Testnet),
            "vpub5Y9M3sStNdsebhdhtCDdr8UEh46QryfGK1HvipXbyeF9YNSSQTYp82YzyQxBddBzP5Zgh4p4zpCmg5cJwfcnRQynmSBguL2JEh8umtXSXHN"
        );
        assert_eq!(
            xpub.to_slip132_string(KeyApplication::SegWitMultisig, Network::Testnet),
            "Vpub5j3SB7BKwbS22Go5prgcgCp3Qr8g5LLrdGwbe5o9MR5ZAZ1MArw6D9Qvn7ufC4QtcYdfZepBt2bGoFE5EtmjZu6TbuJ6JjVJ8RQnMkMTT7U"
        );
    }

    #[test]
    fn xprv_to_slip132_string() {
        let xprv_str = "xprv9xpXFhFpqdQK5owUStFsuAiWUxYpLkvQn1QmVDumBKTvmmjkNEZgpMYoAaAftt3JVeDhRkvyLvrKathDToUMdz2FqRF7JNavF7uboJWArrw";
        let xprv = Xpriv::from_str(xprv_str).unwrap();

        // Mainnet
        assert_eq!(
            xprv.to_slip132_string(KeyApplication::Hashed, Network::Bitcoin),
            xprv_str
        );
        assert_eq!(
            xprv.to_slip132_string(KeyApplication::Nested, Network::Bitcoin),
            "yprvAHenZMvjzJwnw78bHF3W7Fp1evhGHNuuh7vzGcoeZKqopsYyctjFSRCwBn8FtnhDuHLWBEXXobCsUBJnBVtNSDhrhkwXtHQQWqyFBpXETuS"
        );
        assert_eq!(
            xprv.to_slip132_string(KeyApplication::NestedMultisig, Network::Bitcoin),
            "YprvAUYsgbfBZGWAMgHyDuWUwL9pNijXVjbW1PafBt5Bw6gDT47tPJ7XXY4rzV5jTDv88kQV3pXegobNbLvYUj3KahpXYE3wHgsQQaF7mkmDXua"
        );
        assert_eq!(
            xprv.to_slip132_string(KeyApplication::SegWit, Network::Bitcoin),
            "zprvAcV3s2bf8zVGnQKi7bq8KLuWptqiDzuQcETD41hXwLDgsyNCsYtp4Us5Cz5qthM9JvTJvi86GFZRMTvLuCJPETPTa6dxUCDtna2taUzNeUa"
        );
        assert_eq!(
            xprv.to_slip132_string(KeyApplication::SegWitMultisig, Network::Bitcoin),
            "ZprvAoP8zGL6hx3eCyV64GJ79RFKYgsySMazvW6syGy5K746W9w7dxH69bj11h3KT8a3YPXHoJ8D9TwvUdY7CRTLNwW8QZkMsbgtgJJmANdRWza"
        );

        // Testnet
        assert_eq!(
            xprv.to_slip132_string(KeyApplication::Hashed, Network::Testnet),
            "tprv8fVU32aAEuEPgdB17T7P4pLVo5y2aGxR7ZKtMeLDfHxQZNUqMbuSL6vF5kLKuFRcs5kURrYjWHS83kExb1pJT3HrN4TQxjJyADf2F32kmMf"
        );
        assert_eq!(
            xprv.to_slip132_string(KeyApplication::Nested, Network::Testnet),
            "uprv8zKjLhF5PamsXvN7wou1GuRzy47UWtwv2fr793E73JLHcUJ4cG4zxAaP6xHuuA5YGisHBL9Hxwnfw2rXJiEKFGyTEQ9qYe8TRwifdcMUKTP"
        );
        assert_eq!(
            xprv.to_slip132_string(KeyApplication::NestedMultisig, Network::Testnet),
            "Uprv9BDpTvyWxYLExVXVtUMz6ymogr9jjFdWLwVn4JVeR5AhEeryNfTH3HSJufFPTbJSWBwG3v9QrABB4CUHbwPGPm684sGEx3bTKfzYDSPHHCV"
        );
        assert_eq!(
            xprv.to_slip132_string(KeyApplication::SegWit, Network::Testnet),
            "vprv9K9zeMuzYGKMPDZEnAgdUzXW92FvTWwQwnNKvS7zRJiAfa7HrvEZaEEX8AFVu4jTgMz5vojrRc9DpKU62QeL3Wf46jrG8YwwhfnK26J1Pi6"
        );
        assert_eq!(
            xprv.to_slip132_string(KeyApplication::SegWitMultisig, Network::Testnet),
            "Vprv1CMQ2h95oDkM8omHwD22Go9vqpcjv19x3yLpMZkqw9HAL4kaYU7W2eo4c1HqwNPSVN3wBuqrw5HUiA8z3zHz7cb2QFRfWnUkvYDCHhvLxCW"
        );
    }
}
