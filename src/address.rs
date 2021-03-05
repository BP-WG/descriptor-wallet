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

use std::convert::{TryFrom, TryInto};
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use bitcoin::bech32::u5;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::schnorrsig as bip340;
use bitcoin::util::address::{self, Payload};
use bitcoin::{
    Address, Network, PubkeyHash, Script, ScriptHash, WPubkeyHash, WScriptHash,
};

use crate::PubkeyScript;

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
    StrictDecode,
)]
pub struct AddressPayload {
    pub inner: AddressInner,
    pub testnet: bool,
}

impl AddressPayload {
    pub fn from_script(
        script: &Script,
        network: bitcoin::Network,
    ) -> Option<Self> {
        Address::from_script(&script, network)
            .ok_or(address::Error::UncompressedPubkey)
            .and_then(Self::try_from)
            .ok()
    }
}

impl From<AddressPayload> for Address {
    fn from(payload: AddressPayload) -> Self {
        payload.inner.into_address(if payload.testnet {
            Network::Testnet
        } else {
            Network::Bitcoin
        })
    }
}

impl TryFrom<Address> for AddressPayload {
    type Error = address::Error;

    fn try_from(address: Address) -> Result<Self, Self::Error> {
        Ok(AddressPayload {
            inner: address.payload.try_into()?,
            testnet: address.network != bitcoin::Network::Bitcoin,
        })
    }
}

impl From<AddressPayload> for PubkeyScript {
    fn from(payload: AddressPayload) -> Self {
        Address::from(payload).script_pubkey().into()
    }
}

impl Display for AddressPayload {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&Address::from(*self), f)
    }
}

impl FromStr for AddressPayload {
    type Err = address::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Address::from_str(s).and_then(AddressPayload::try_from)
    }
}

/// See also [`descriptor::Compact`] as a non-copy alternative supporting
/// bare/custom scripts
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
    StrictDecode,
)]
pub enum AddressInner {
    #[from]
    PubkeyHash(PubkeyHash),

    #[from]
    ScriptHash(ScriptHash),

    #[from]
    WPubkeyHash(WPubkeyHash),

    #[from]
    WScriptHash(WScriptHash),

    #[from]
    Taproot(bip340::PublicKey),
}

impl AddressInner {
    pub fn into_address(self, network: Network) -> Address {
        Address {
            payload: self.into(),
            network,
        }
    }

    pub fn from_address(address: Address) -> Option<Self> {
        Self::from_payload(address.payload)
    }

    pub fn from_payload(payload: Payload) -> Option<Self> {
        Some(match payload {
            Payload::PubkeyHash(pkh) => AddressInner::PubkeyHash(pkh),
            Payload::ScriptHash(sh) => AddressInner::ScriptHash(sh),
            Payload::WitnessProgram { version, program }
                if version.to_u8() == 0 && program.len() == 20 =>
            {
                AddressInner::WPubkeyHash(
                    WPubkeyHash::from_slice(&program)
                        .expect("WPubkeyHash vec length estimation is broken"),
                )
            }
            Payload::WitnessProgram { version, program }
                if version.to_u8() == 0 && program.len() == 32 =>
            {
                AddressInner::WScriptHash(
                    WScriptHash::from_slice(&program)
                        .expect("WScriptHash vec length estimation is broken"),
                )
            }
            Payload::WitnessProgram { version, program }
                if version.to_u8() == 1 && program.len() == 32 =>
            {
                AddressInner::Taproot(
                    bip340::PublicKey::from_slice(&program).expect(
                        "Taproot public key vec length estimation is broken",
                    ),
                )
            }
            _ => return None,
        })
    }

    pub fn from_script(script: &Script) -> Option<Self> {
        Address::from_script(&script, Network::Bitcoin)
            .and_then(Self::from_address)
    }
}

impl From<AddressInner> for Payload {
    fn from(ap: AddressInner) -> Self {
        match ap {
            AddressInner::PubkeyHash(pkh) => Payload::PubkeyHash(pkh),
            AddressInner::ScriptHash(sh) => Payload::ScriptHash(sh),
            AddressInner::WPubkeyHash(wpkh) => Payload::WitnessProgram {
                version: u5::try_from_u8(0).unwrap(),
                program: wpkh.to_vec(),
            },
            AddressInner::WScriptHash(wsh) => Payload::WitnessProgram {
                version: u5::try_from_u8(0).unwrap(),
                program: wsh.to_vec(),
            },
            AddressInner::Taproot(tr) => Payload::WitnessProgram {
                version: u5::try_from_u8(1).unwrap(),
                program: tr.serialize().to_vec(),
            },
        }
    }
}

impl TryFrom<Payload> for AddressInner {
    type Error = address::Error;

    fn try_from(payload: Payload) -> Result<Self, Self::Error> {
        Ok(match payload {
            Payload::PubkeyHash(hash) => AddressInner::PubkeyHash(hash),
            Payload::ScriptHash(hash) => AddressInner::ScriptHash(hash),
            Payload::WitnessProgram { version, program }
                if version.to_u8() == 0u8 =>
            {
                if program.len() == 32 {
                    AddressInner::WScriptHash(
                        WScriptHash::from_slice(&program).expect(
                            "WScriptHash is broken: it must be 32 byte len",
                        ),
                    )
                } else if program.len() == 20 {
                    AddressInner::WPubkeyHash(
                        WPubkeyHash::from_slice(&program).expect(
                            "WScriptHash is broken: it must be 20 byte len",
                        ),
                    )
                } else {
                    panic!(
                        "bitcoin::Address is broken: v0 witness program must be \
                        either 32 or 20 bytes len"
                    )
                }
            }
            Payload::WitnessProgram { version, program }
                if version.to_u8() == 1u8 =>
            {
                if program.len() == 32 {
                    AddressInner::Taproot(bip340::PublicKey::from_slice(&program).expect(
                        "bip340::PublicKey is broken: it must be 32 byte len",
                    ))
                } else {
                    panic!(
                        "bitcoin::Address is broken: v1 witness program must be \
                        either 32 bytes len"
                    )
                }
            }
            Payload::WitnessProgram { version, .. } => {
                return Err(address::Error::InvalidWitnessVersion(
                    version.to_u8(),
                ))
            }
        })
    }
}

impl From<AddressInner> for PubkeyScript {
    fn from(ap: AddressInner) -> Self {
        ap.into_address(Network::Bitcoin).script_pubkey().into()
    }
}

impl Display for AddressInner {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(
            &self.into_address(if f.alternate() {
                Network::Testnet
            } else {
                Network::Bitcoin
            }),
            f,
        )
    }
}

impl FromStr for AddressInner {
    type Err = bitcoin::util::address::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Address::from_str(s).and_then(|addr| {
            AddressInner::from_address(addr)
                .ok_or(Self::Err::InvalidWitnessVersion(2))
        })
    }
}
