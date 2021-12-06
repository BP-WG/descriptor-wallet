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

use amplify::Slice32;
use bitcoin::secp256k1;

use crate::ProprietaryKey;

// TODO: Move this module to BP Core lib

pub const PSBT_DBC_PREFIX: &[u8] = b"DBC";
pub const PSBT_IN_DBC_P2C_TWEAK: u8 = 0;

/// Extension trait to work with deterministic bitcoin commitment P2C tweaks
/// applied to public keys in PSBT inputs.
pub trait InputP2cTweak {
    /// Adds information about DBC P2C public key to PSBT input
    fn set_dbc_p2c_tweak(&mut self, pubkey: secp256k1::PublicKey, tweak: Slice32);
    /// Finds a tweak for the provided bitcoin public key, if is known
    fn dbc_p2c_tweak(&self, pk: secp256k1::PublicKey) -> Option<Slice32>;
}

impl InputP2cTweak for crate::Input {
    fn set_dbc_p2c_tweak(&mut self, pubkey: secp256k1::PublicKey, tweak: Slice32) {
        let mut value = pubkey.serialize().to_vec();
        value.extend(&tweak[..]);
        self.proprietary.insert(
            ProprietaryKey {
                prefix: PSBT_DBC_PREFIX.to_vec(),
                subtype: PSBT_IN_DBC_P2C_TWEAK,
                key: vec![],
            },
            value,
        );
    }

    fn dbc_p2c_tweak(&self, pk: secp256k1::PublicKey) -> Option<Slice32> {
        self.proprietary.iter().find_map(
            |(
                ProprietaryKey {
                    prefix,
                    subtype,
                    key,
                },
                value,
            )| {
                if prefix.as_slice() == PSBT_DBC_PREFIX
                    && *subtype == PSBT_IN_DBC_P2C_TWEAK
                    && key == &Vec::<u8>::new()
                    && value.len() == 33 + 32
                {
                    secp256k1::PublicKey::from_slice(&value[..33])
                        .ok()
                        .and_then(|pubkey| {
                            if pk == pubkey {
                                Slice32::from_slice(&value[33..])
                            } else {
                                None
                            }
                        })
                } else {
                    None
                }
            },
        )
    }
}
