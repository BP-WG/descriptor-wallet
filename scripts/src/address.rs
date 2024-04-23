// BP foundation libraries Bitcoin crates implementing the foundations of
// Bitcoin protocol by LNP/BP Association (https://lnp-bp.org)
//
// Written in 2020-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// This software is distributed without any warranty.
//
// You should have received a copy of the Apache-2.0 License
// along with this software.
// If not, see <https://opensource.org/licenses/Apache-2.0>.

//! Address-related types for detailed payload analysis and memory-efficient
//! processing.

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use amplify::Wrapper;
use bitcoin::hashes::{hex, Hash};
use bitcoin::schnorr::TweakedPublicKey;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::util::address::{self, Payload, WitnessVersion};
use bitcoin::{secp256k1, Address, PubkeyHash, Script, ScriptHash, WPubkeyHash, WScriptHash};

use crate::PubkeyScript;

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
    /// wrapped in P2SH bitcoin
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
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
pub struct AddressCompat {
    /// Address payload (see [`AddressPayload`]).
    pub payload: AddressPayload,

    /// A type of the network used by the address
    pub network: AddressNetwork,
}

impl AddressCompat {
    /// Constructs compatible address for a given `scriptPubkey`.
    /// Returns `None` if the uncompressed key is provided or `scriptPubkey`
    /// can't be represented as an address.
    pub fn from_script(script: &PubkeyScript, network: AddressNetwork) -> Option<Self> {
        Address::from_script(script.as_inner(), network.bitcoin_network())
            .map_err(|_| address::Error::UncompressedPubkey)
            .and_then(Self::try_from)
            .ok()
    }

    /// Returns script corresponding to the given address.
    pub fn script_pubkey(self) -> PubkeyScript { self.payload.script_pubkey() }

    /// Returns if the address is testnet-, signet- or regtest-specific
    pub fn is_testnet(self) -> bool { self.network != AddressNetwork::Mainnet }
}

impl From<AddressCompat> for Address {
    fn from(compact: AddressCompat) -> Self {
        compact
            .payload
            .into_address(compact.network.bitcoin_network())
    }
}

impl TryFrom<Address> for AddressCompat {
    type Error = address::Error;

    fn try_from(address: Address) -> Result<Self, Self::Error> {
        Ok(AddressCompat {
            payload: address.payload.try_into()?,
            network: address.network.into(),
        })
    }
}

impl From<AddressCompat> for PubkeyScript {
    fn from(compact: AddressCompat) -> Self { Address::from(compact).script_pubkey().into() }
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

/// Internal address content. Consists of serialized hashes or x-only key value.
///
/// See also `descriptors::Compact` as a non-copy alternative supporting
/// bare/custom scripts.
#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From
)]
pub enum AddressPayload {
    /// P2PKH payload.
    #[from]
    #[display("raw_pkh({0})")]
    PubkeyHash(PubkeyHash),

    /// P2SH and SegWit nested (legacy) P2WPKH/WSH-in-P2SH payloads.
    #[from]
    #[display("raw_sh({0})")]
    ScriptHash(ScriptHash),

    /// P2WPKH payload.
    #[from]
    #[display("raw_wpkh({0})")]
    WPubkeyHash(WPubkeyHash),

    /// P2WSH payload.
    #[from]
    #[display("raw_wsh({0})")]
    WScriptHash(WScriptHash),

    /// P2TR payload.
    #[from]
    #[display("raw_tr({output_key})")]
    Taproot {
        /// Taproot output key (tweaked key)
        output_key: TweakedPublicKey,
    },
}

impl AddressPayload {
    /// Constructs [`Address`] from the payload.
    pub fn into_address(self, network: bitcoin::Network) -> Address {
        Address {
            payload: self.into(),
            network,
        }
    }

    /// Constructs payload from a given address. Fails on future (post-taproot)
    /// witness types with `None`.
    pub fn from_address(address: Address) -> Option<Self> { Self::from_payload(address.payload) }

    /// Constructs payload from rust-bitcoin [`Payload`]. Fails on future
    /// (post-taproot) witness types with `None`.
    pub fn from_payload(payload: Payload) -> Option<Self> {
        Some(match payload {
            Payload::PubkeyHash(pkh) => AddressPayload::PubkeyHash(pkh),
            Payload::ScriptHash(sh) => AddressPayload::ScriptHash(sh),
            Payload::WitnessProgram { version, program }
                if version.to_num() == 0 && program.len() == 20 =>
            {
                AddressPayload::WPubkeyHash(
                    WPubkeyHash::from_slice(&program)
                        .expect("WPubkeyHash vec length estimation is broken"),
                )
            }
            Payload::WitnessProgram { version, program }
                if version.to_num() == 0 && program.len() == 32 =>
            {
                AddressPayload::WScriptHash(
                    WScriptHash::from_slice(&program)
                        .expect("WScriptHash vec length estimation is broken"),
                )
            }
            Payload::WitnessProgram { version, program }
                if version.to_num() == 1 && program.len() == 32 =>
            {
                AddressPayload::Taproot {
                    output_key: TweakedPublicKey::dangerous_assume_tweaked(
                        XOnlyPublicKey::from_slice(&program)
                            .expect("Taproot public key vec length estimation is broken"),
                    ),
                }
            }
            _ => return None,
        })
    }

    /// Constructs payload from a given `scriptPubkey`. Fails on future
    /// (post-taproot) witness types with `None`.
    pub fn from_script(script: &PubkeyScript) -> Option<Self> {
        Address::from_script(script.as_inner(), bitcoin::Network::Bitcoin)
            .ok()
            .and_then(Self::from_address)
    }

    /// Returns script corresponding to the given address.
    pub fn script_pubkey(self) -> PubkeyScript {
        match self {
            AddressPayload::PubkeyHash(hash) => Script::new_p2pkh(&hash),
            AddressPayload::ScriptHash(hash) => Script::new_p2sh(&hash),
            AddressPayload::WPubkeyHash(hash) => Script::new_v0_p2wpkh(&hash),
            AddressPayload::WScriptHash(hash) => Script::new_v0_p2wsh(&hash),
            AddressPayload::Taproot { output_key } => Script::new_v1_p2tr_tweaked(output_key),
        }
        .into()
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
            Payload::WitnessProgram { version, program } if version.to_num() == 0u8 => {
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
            Payload::WitnessProgram { version, program } if version.to_num() == 1u8 => {
                if program.len() == 32 {
                    AddressPayload::Taproot {
                        output_key: TweakedPublicKey::dangerous_assume_tweaked(
                            XOnlyPublicKey::from_slice(&program)
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
                return Err(address::Error::InvalidWitnessVersion(version.to_num()))
            }
        })
    }
}

impl From<AddressPayload> for PubkeyScript {
    fn from(ap: AddressPayload) -> Self {
        ap.into_address(bitcoin::Network::Bitcoin)
            .script_pubkey()
            .into()
    }
}

/// Errors parsing address strings.
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
        let mut split = s.trim_end_matches(')').split('(');
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
                output_key: TweakedPublicKey::dangerous_assume_tweaked(XOnlyPublicKey::from_str(
                    hash,
                )?),
            },
            (Some(prefix), ..) => return Err(AddressParseError::UnknownPrefix(prefix.to_owned())),
            (None, ..) => return Err(AddressParseError::PrefixAbsent),
        })
    }
}

/// Address format
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum AddressFormat {
    /// Pay-to-public key hash
    #[display("P2PKH")]
    P2pkh,

    /// Pay-to-script hash
    #[display("P2SH")]
    P2sh,

    /// Pay-to-witness public key hash
    #[display("P2WPKH")]
    P2wpkh,

    /// Pay-to-witness script pash
    #[display("P2WSH")]
    P2wsh,

    /// Pay-to-taproot
    #[display("P2TR")]
    P2tr,

    /// Future witness address
    #[display("P2W{0}")]
    Future(WitnessVersion),
}

impl AddressFormat {
    /// Returns witness version used by the address format.
    /// Returns `None` for pre-SegWit address formats.
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
                if version.to_num() == 0 && program.len() == 32 =>
            {
                AddressFormat::P2wsh
            }
            Payload::WitnessProgram { version, program }
                if version.to_num() == 0 && program.len() == 20 =>
            {
                AddressFormat::P2wpkh
            }
            Payload::WitnessProgram { version, .. } if version.to_num() == 1 => AddressFormat::P2tr,
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

/// Bitcoin network used by the address
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum AddressNetwork {
    /// Bitcoin mainnet
    #[display("mainnet")]
    Mainnet,

    /// Bitcoin testnet and signet
    #[display("testnet")]
    Testnet,

    /// Bitcoin regtest networks
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
    fn from(network: bitcoin::Network) -> Self {
        match network {
            bitcoin::Network::Bitcoin => AddressNetwork::Mainnet,
            bitcoin::Network::Testnet => AddressNetwork::Testnet,
            bitcoin::Network::Signet => AddressNetwork::Testnet,
            bitcoin::Network::Regtest => AddressNetwork::Regtest,
        }
    }
}

impl AddressNetwork {
    /// This convertor is not public since there is an ambiguity which type
    /// must correspond to the [`AddressNetwork::Testnet`]. Thus, clients of
    /// this library must propvide their custom convertors taking decisions
    /// on this question.
    fn bitcoin_network(self) -> bitcoin::Network {
        match self {
            AddressNetwork::Mainnet => bitcoin::Network::Bitcoin,
            AddressNetwork::Testnet => bitcoin::Network::Testnet,
            AddressNetwork::Regtest => bitcoin::Network::Regtest,
        }
    }

    /// Detects whether the network is a kind of test network (testnet, signet,
    /// regtest).
    pub fn is_testnet(self) -> bool { self != Self::Mainnet }
}
