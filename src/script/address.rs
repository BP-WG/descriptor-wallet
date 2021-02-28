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

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use bitcoin::bech32::u5;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::schnorrsig as bip340;
use bitcoin::util::address::Payload;
use bitcoin::{
    Address, Network, PubkeyHash, Script, ScriptHash, WPubkeyHash, WScriptHash,
};

use crate::PubkeyScript;

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
pub enum AddressPayload {
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

impl AddressPayload {
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
            Payload::PubkeyHash(pkh) => AddressPayload::PubkeyHash(pkh),
            Payload::ScriptHash(sh) => AddressPayload::ScriptHash(sh),
            Payload::WitnessProgram { version, program }
                if version.to_u8() == 0 && program.len() == 20 =>
            {
                AddressPayload::WPubkeyHash(
                    WPubkeyHash::from_slice(&program)
                        .expect("WPubkeyHash vec length estimation is broken"),
                )
            }
            Payload::WitnessProgram { version, program }
                if version.to_u8() == 0 && program.len() == 32 =>
            {
                AddressPayload::WScriptHash(
                    WScriptHash::from_slice(&program)
                        .expect("WScriptHash vec length estimation is broken"),
                )
            }
            Payload::WitnessProgram { version, program }
                if version.to_u8() == 1 && program.len() == 32 =>
            {
                AddressPayload::Taproot(
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

impl From<AddressPayload> for Payload {
    fn from(ap: AddressPayload) -> Self {
        match ap {
            AddressPayload::PubkeyHash(pkh) => Payload::PubkeyHash(pkh),
            AddressPayload::ScriptHash(sh) => Payload::ScriptHash(sh),
            AddressPayload::WPubkeyHash(wpkh) => Payload::WitnessProgram {
                version: u5::try_from_u8(0).unwrap(),
                program: wpkh.to_vec(),
            },
            AddressPayload::WScriptHash(wsh) => Payload::WitnessProgram {
                version: u5::try_from_u8(0).unwrap(),
                program: wsh.to_vec(),
            },
            AddressPayload::Taproot(tr) => Payload::WitnessProgram {
                version: u5::try_from_u8(1).unwrap(),
                program: tr.serialize().to_vec(),
            },
        }
    }
}

impl From<AddressPayload> for PubkeyScript {
    fn from(ap: AddressPayload) -> Self {
        ap.into_address(Network::Bitcoin).script_pubkey().into()
    }
}

impl Display for AddressPayload {
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

impl FromStr for AddressPayload {
    type Err = bitcoin::util::address::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Address::from_str(s).and_then(|addr| {
            AddressPayload::from_address(addr)
                .ok_or(Self::Err::InvalidWitnessVersion(2))
        })
    }
}
