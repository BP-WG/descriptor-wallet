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

use std::convert::{TryFrom, TryInto};
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use bitcoin::hashes::{hex, Hash};
use bitcoin::schnorr::TweakedPublicKey;
use bitcoin::secp256k1::schnorrsig as bip340;
use bitcoin::util::address::{self, Payload, WitnessVersion};
use bitcoin::{
    secp256k1, Address, Network, PubkeyHash, Script, ScriptHash, WPubkeyHash, WScriptHash,
};
use bitcoin_scripts::PubkeyScript;

/// Defines which witness version may have an address.
///
/// The structure is required to support some ambiguity on the witness version
/// used by some address, since `Option<`[`WitnessVersion`]`>` can't cover that
/// ambiguity (see details in [`SegWitInfo::Ambiguous`] description).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SegWitInfo {
    /// P2PKH addresses
    PreSegWit,

    /// P2SH addresses, which may be pre-segwit, segwit v0 (P2WPK/WSH-in-P2SH),
    /// non-taproot segwit v1 wrapped in P2SH, or future segwit versions
    /// wrapped in P2SH scripts
    Ambiguous,

    /// Address has a clearly defined segwit version, i.e. P2WPKH, P2WSH, P2TR
    /// or future non-P2SH-wrapped segwit address
    SegWit(WitnessVersion),
}

impl SegWitInfo {
    /// Detects [`WitnessVersion`] used in the current segwit. Returns [`None`]
    /// for both pre-segwit and P2SH (ambiguous) addresses.
    #[inline]
    pub fn witness_version(self) -> Option<WitnessVersion> {
        match self {
            SegWitInfo::PreSegWit => None,
            SegWitInfo::Ambiguous => None,
            SegWitInfo::SegWit(version) => Some(version),
        }
    }
}

/// See also [`bitcoin::Address`] as a non-copy alternative supporting
/// future witness program versions
#[derive(
    Copy,
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    From,
    StrictEncode,
    StrictDecode
)]
pub struct AddressCompat {
    pub inner: AddressPayload,
    pub testnet: bool,
}

impl AddressCompat {
    pub fn from_script(script: &Script, network: bitcoin::Network) -> Option<Self> {
        Address::from_script(script, network)
            .ok_or(address::Error::UncompressedPubkey)
            .and_then(Self::try_from)
            .ok()
    }
}

impl From<AddressCompat> for Address {
    fn from(payload: AddressCompat) -> Self {
        payload.inner.into_address(if payload.testnet {
            Network::Testnet
        } else {
            Network::Bitcoin
        })
    }
}

impl TryFrom<Address> for AddressCompat {
    type Error = address::Error;

    fn try_from(address: Address) -> Result<Self, Self::Error> {
        Ok(AddressCompat {
            inner: address.payload.try_into()?,
            testnet: address.network != bitcoin::Network::Bitcoin,
        })
    }
}

impl From<AddressCompat> for PubkeyScript {
    fn from(payload: AddressCompat) -> Self { Address::from(payload).script_pubkey().into() }
}

impl Display for AddressCompat {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { Display::fmt(&Address::from(*self), f) }
}

impl FromStr for AddressCompat {
    type Err = address::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Address::from_str(s).and_then(AddressCompat::try_from)
    }
}

// See also [`descriptor::Compact`] as a non-copy alternative supporting
// bare/custom scripts
#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From
)]
#[derive(StrictEncode, StrictDecode)]
pub enum AddressPayload {
    #[from]
    #[display("pkh:{0}")]
    PubkeyHash(PubkeyHash),

    #[from]
    #[display("sh:{0}")]
    ScriptHash(ScriptHash),

    #[from]
    #[display("wpkh:{0}")]
    WPubkeyHash(WPubkeyHash),

    #[from]
    #[display("wsh:{0}")]
    WScriptHash(WScriptHash),

    #[from]
    #[display("tr:{output_key}")]
    Taproot { output_key: TweakedPublicKey },
}

impl AddressPayload {
    pub fn into_address(self, network: Network) -> Address {
        Address {
            payload: self.into(),
            network,
        }
    }

    pub fn from_address(address: Address) -> Option<Self> { Self::from_payload(address.payload) }

    pub fn from_payload(payload: Payload) -> Option<Self> {
        Some(match payload {
            Payload::PubkeyHash(pkh) => AddressPayload::PubkeyHash(pkh),
            Payload::ScriptHash(sh) => AddressPayload::ScriptHash(sh),
            Payload::WitnessProgram { version, program }
                if version.into_num() == 0 && program.len() == 20 =>
            {
                AddressPayload::WPubkeyHash(
                    WPubkeyHash::from_slice(&program)
                        .expect("WPubkeyHash vec length estimation is broken"),
                )
            }
            Payload::WitnessProgram { version, program }
                if version.into_num() == 0 && program.len() == 32 =>
            {
                AddressPayload::WScriptHash(
                    WScriptHash::from_slice(&program)
                        .expect("WScriptHash vec length estimation is broken"),
                )
            }
            Payload::WitnessProgram { version, program }
                if version.into_num() == 1 && program.len() == 32 =>
            {
                AddressPayload::Taproot {
                    output_key: TweakedPublicKey::dangerous_assume_tweaked(
                        bip340::PublicKey::from_slice(&program)
                            .expect("Taproot public key vec length estimation is broken"),
                    ),
                }
            }
            _ => return None,
        })
    }

    pub fn from_script(script: &Script) -> Option<Self> {
        Address::from_script(script, Network::Bitcoin).and_then(Self::from_address)
    }
}

impl From<AddressPayload> for Payload {
    fn from(ap: AddressPayload) -> Self {
        match ap {
            AddressPayload::PubkeyHash(pkh) => Payload::PubkeyHash(pkh),
            AddressPayload::ScriptHash(sh) => Payload::ScriptHash(sh),
            AddressPayload::WPubkeyHash(wpkh) => Payload::WitnessProgram {
                version: WitnessVersion::V0,
                program: wpkh.to_vec(),
            },
            AddressPayload::WScriptHash(wsh) => Payload::WitnessProgram {
                version: WitnessVersion::V0,
                program: wsh.to_vec(),
            },
            AddressPayload::Taproot { output_key } => Payload::WitnessProgram {
                version: WitnessVersion::V1,
                program: output_key.serialize().to_vec(),
            },
        }
    }
}

impl TryFrom<Payload> for AddressPayload {
    type Error = address::Error;

    fn try_from(payload: Payload) -> Result<Self, Self::Error> {
        Ok(match payload {
            Payload::PubkeyHash(hash) => AddressPayload::PubkeyHash(hash),
            Payload::ScriptHash(hash) => AddressPayload::ScriptHash(hash),
            Payload::WitnessProgram { version, program } if version.into_num() == 0u8 => {
                if program.len() == 32 {
                    AddressPayload::WScriptHash(
                        WScriptHash::from_slice(&program)
                            .expect("WScriptHash is broken: it must be 32 byte len"),
                    )
                } else if program.len() == 20 {
                    AddressPayload::WPubkeyHash(
                        WPubkeyHash::from_slice(&program)
                            .expect("WScriptHash is broken: it must be 20 byte len"),
                    )
                } else {
                    panic!(
                        "bitcoin::Address is broken: v0 witness program must be either 32 or 20 \
                         bytes len"
                    )
                }
            }
            Payload::WitnessProgram { version, program } if version.into_num() == 1u8 => {
                if program.len() == 32 {
                    AddressPayload::Taproot {
                        output_key: TweakedPublicKey::dangerous_assume_tweaked(
                            bip340::PublicKey::from_slice(&program)
                                .expect("bip340::PublicKey is broken: it must be 32 byte len"),
                        ),
                    }
                } else {
                    panic!(
                        "bitcoin::Address is broken: v1 witness program must be either 32 bytes \
                         len"
                    )
                }
            }
            Payload::WitnessProgram { version, .. } => {
                return Err(address::Error::InvalidWitnessVersion(version.into_num()))
            }
        })
    }
}

impl From<AddressPayload> for PubkeyScript {
    fn from(ap: AddressPayload) -> Self { ap.into_address(Network::Bitcoin).script_pubkey().into() }
}

#[derive(
    Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error, From
)]
#[display(doc_comments)]
pub enum AddressParseError {
    /// unknown address payload prefix `{0}`; expected `pkh`, `sh`, `wpkh`,
    /// `wsh` and `pkxo` only
    UnknownPrefix(String),

    /// unrecognized address payload string format
    UnrecognizedStringFormat,

    /// address payload must be prefixed by pyaload format prefix, indicating
    /// specific form of hash or a public key used inside the address
    PrefixAbsent,

    /// wrong address payload data
    #[from(hex::Error)]
    WrongPayloadHashData,

    /// wrong BIP340 public key (xcoord-only)
    #[from(secp256k1::Error)]
    WrongPublicKeyData,

    /// unrecognized address network string; only `mainnet`, `testnet` and
    /// `regtest` are possible at address level
    UnrecognizedAddressNetwork,

    /// unrecognized address format string; must be one of `P2PKH`, `P2SH`,
    /// `P2WPKH`, `P2WSH`, `P2TR`
    UnrecognizedAddressFormat,

    /// wrong witness version
    WrongWitnessVersion,
}

impl FromStr for AddressPayload {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_lowercase();
        let mut split = s.split(':');
        Ok(match (split.next(), split.next(), split.next()) {
            (_, _, Some(_)) => return Err(AddressParseError::UnrecognizedStringFormat),
            (Some("pkh"), Some(hash), None) => {
                AddressPayload::PubkeyHash(PubkeyHash::from_str(hash)?)
            }
            (Some("sh"), Some(hash), None) => {
                AddressPayload::ScriptHash(ScriptHash::from_str(hash)?)
            }
            (Some("wpkh"), Some(hash), None) => {
                AddressPayload::WPubkeyHash(WPubkeyHash::from_str(hash)?)
            }
            (Some("wsh"), Some(hash), None) => {
                AddressPayload::WScriptHash(WScriptHash::from_str(hash)?)
            }
            (Some("pkxo"), Some(hash), None) => AddressPayload::Taproot {
                output_key: TweakedPublicKey::dangerous_assume_tweaked(
                    bip340::PublicKey::from_str(hash)?,
                ),
            },
            (Some(prefix), ..) => return Err(AddressParseError::UnknownPrefix(prefix.to_owned())),
            (None, ..) => return Err(AddressParseError::PrefixAbsent),
        })
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum AddressFormat {
    #[display("P2PKH")]
    P2pkh,

    #[display("P2SH")]
    P2sh,

    #[display("P2WPKH")]
    P2wpkh,

    #[display("P2WSH")]
    P2wsh,

    #[display("P2TR")]
    P2tr,

    #[display("P2W{0}")]
    Future(WitnessVersion),
}

impl AddressFormat {
    pub fn witness_version(self) -> Option<WitnessVersion> {
        match self {
            AddressFormat::P2pkh => None,
            AddressFormat::P2sh => None,
            AddressFormat::P2wpkh | AddressFormat::P2wsh => Some(WitnessVersion::V0),
            AddressFormat::P2tr => Some(WitnessVersion::V1),
            AddressFormat::Future(ver) => Some(ver),
        }
    }
}

impl From<Address> for AddressFormat {
    fn from(address: Address) -> Self { address.payload.into() }
}

impl From<Payload> for AddressFormat {
    fn from(payload: Payload) -> Self {
        match payload {
            Payload::PubkeyHash(_) => AddressFormat::P2pkh,
            Payload::ScriptHash(_) => AddressFormat::P2sh,
            Payload::WitnessProgram { version, program }
                if version.into_num() == 0 && program.len() == 32 =>
            {
                AddressFormat::P2wsh
            }
            Payload::WitnessProgram { version, program }
                if version.into_num() == 0 && program.len() == 20 =>
            {
                AddressFormat::P2wpkh
            }
            Payload::WitnessProgram { version, .. } if version.into_num() == 1 => {
                AddressFormat::P2tr
            }
            Payload::WitnessProgram { version, .. } => AddressFormat::Future(version),
        }
    }
}

impl FromStr for AddressFormat {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        #[allow(clippy::match_str_case_mismatch)]
        Ok(match s.to_uppercase().as_str() {
            "P2PKH" => AddressFormat::P2pkh,
            "P2SH" => AddressFormat::P2sh,
            "P2WPKH" => AddressFormat::P2wpkh,
            "P2WSH" => AddressFormat::P2wsh,
            "P2TR" => AddressFormat::P2tr,
            s if s.starts_with("P2W") => AddressFormat::Future(
                WitnessVersion::from_str(&s[3..])
                    .map_err(|_| AddressParseError::WrongWitnessVersion)?,
            ),
            _ => return Err(AddressParseError::UnrecognizedAddressFormat),
        })
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum AddressNetwork {
    #[display("mainnet")]
    Mainnet,

    #[display("testnet")]
    Testnet,

    #[display("regtest")]
    Regtest,
}

impl FromStr for AddressNetwork {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "mainnet" => AddressNetwork::Mainnet,
            "testnet" => AddressNetwork::Testnet,
            "regtest" => AddressNetwork::Regtest,
            _ => return Err(AddressParseError::UnrecognizedAddressNetwork),
        })
    }
}

impl From<Address> for AddressNetwork {
    fn from(address: Address) -> Self { address.network.into() }
}

impl From<bitcoin::Network> for AddressNetwork {
    fn from(network: Network) -> Self {
        match network {
            Network::Bitcoin => AddressNetwork::Mainnet,
            Network::Testnet => AddressNetwork::Testnet,
            Network::Signet => AddressNetwork::Testnet,
            Network::Regtest => AddressNetwork::Regtest,
        }
    }
}
