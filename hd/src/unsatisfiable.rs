// Descriptor wallet library extending bitcoin & miniscript functionality
// by LNP/BP Association (https://lnp-bp.org)
// Written in 2020-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the Apache-2.0 License
// along with this software.
// If not, see <https://opensource.org/licenses/Apache-2.0>.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{self, PublicKey, SECP256K1};
use bitcoin::util::bip32::ExtendedPubKey;

use crate::{TerminalStep, TrackingAccount, XpubRef};

/// Extension trait for types containing EC keys, which can be made provably
/// unspendable
pub trait UnsatisfiableKey {
    /// A parameter supplied to [`UnsatisfiableKey::unsatisfiable_key`], like an
    /// information on the use of testnet for extended keys, or derivation path
    /// for key templates.
    type Param;

    /// Generates provably unspendable key version
    fn unsatisfiable_key(_: Self::Param) -> Self;
}

impl UnsatisfiableKey for PublicKey {
    type Param = ();

    fn unsatisfiable_key(_: Self::Param) -> Self {
        let mut unspendable_key = PublicKey::from_secret_key(SECP256K1, &secp256k1::ONE_KEY);
        unspendable_key
            .add_exp_assign(SECP256K1, &sha256::Hash::hash(&unspendable_key.serialize()))
            .unwrap();
        unspendable_key
    }
}

impl UnsatisfiableKey for ExtendedPubKey {
    type Param = bool;

    fn unsatisfiable_key(testnet: Self::Param) -> Self {
        let unspendable_key = PublicKey::unsatisfiable_key(());
        let mut buf = Vec::with_capacity(78);
        buf.extend(if testnet {
            [0x04u8, 0x35, 0x87, 0xCF]
        } else {
            [0x04u8, 0x88, 0xB2, 0x1E]
        });
        buf.extend([0u8; 5]); // depth + fingerprint
        buf.extend([0u8; 4]); // child no
        buf.extend(&unspendable_key.serialize()[1..]);
        buf.extend(&unspendable_key.serialize());
        ExtendedPubKey::decode(&buf).expect("broken unspendable key construction")
    }
}

impl UnsatisfiableKey for TrackingAccount {
    type Param = (bool, Vec<TerminalStep>);

    fn unsatisfiable_key(param: Self::Param) -> Self {
        let (testnet, terminal_path) = param;
        TrackingAccount {
            master: XpubRef::Unknown,
            account_path: vec![],
            account_xpub: ExtendedPubKey::unsatisfiable_key(testnet),
            revocation_seal: None,
            terminal_path,
        }
    }
}
