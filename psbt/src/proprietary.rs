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

use std::collections::BTreeMap;

use amplify::Slice32;
use bitcoin::PublicKey;

use crate::ProprietaryKey;

pub const PSBT_WALLET_PREFIX: &[u8] = b"descriptor-wallet";
pub const PSBT_WALLET_IN_TWEAK: u8 = 0;

pub trait ProprietaryWalletInput {
    fn p2c_tweak_add(&mut self, pubkey: PublicKey, tweak: Slice32);
    fn p2c_tweak(&self) -> BTreeMap<PublicKey, Slice32>;
}

impl ProprietaryWalletInput for crate::v0::Input {
    fn p2c_tweak_add(&mut self, pubkey: PublicKey, tweak: Slice32) {
        self.proprietary.insert(
            ProprietaryKey {
                prefix: PSBT_WALLET_PREFIX.to_vec(),
                subtype: PSBT_WALLET_IN_TWEAK,
                key: pubkey.to_bytes(),
            },
            tweak.to_vec(),
        );
    }

    fn p2c_tweak(&self) -> BTreeMap<PublicKey, Slice32> {
        self.proprietary
            .iter()
            .filter_map(
                |(
                    ProprietaryKey {
                        prefix,
                        subtype,
                        key,
                    },
                    value,
                )| {
                    if prefix.as_slice() == PSBT_WALLET_PREFIX && *subtype == PSBT_WALLET_IN_TWEAK {
                        PublicKey::from_slice(key)
                            .ok()
                            .and_then(|pk| Slice32::from_slice(value).map(|tweak| (pk, tweak)))
                    } else {
                        None
                    }
                },
            )
            .collect()
    }
}
