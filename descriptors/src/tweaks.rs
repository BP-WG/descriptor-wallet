// Descriptor wallet library extending bitcoin & miniscript functionality
// by LNP/BP Association (https://lnp-bp.org)
// Written in 2020-2022 by
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

use bitcoin::hashes::sha256;
use bitcoin::secp256k1;

pub enum OutputTweak {
    TapReturn(TapretTweak),
    P2cKey(PubkeyTweak),
    P2cScript(ScriptTweak),
}

pub struct TapretTweak(sha256::Hash);

pub struct PubkeyTweak(secp256k1::SecretKey);

pub struct ScriptTweak {
    pub tweak: secp256k1::SecretKey,
    pub original_key: bitcoin::PublicKey,
}

#[cfg(feature = "miniscript")]
mod ms {
    use super::*;
    use bitcoin::schnorr::UntweakedPublicKey;
    use bitcoin::{Address, Network, Script, XOnlyPublicKey};
    use bitcoin_hd::{DeriveError, DescriptorDerive, TrackingAccount, UnhardenedIndex};
    use miniscript::descriptor::Tr;
    use miniscript::{Descriptor, DescriptorTrait, Error, MiniscriptKey, Satisfier, ToPublicKey};

    /// `OP_RETURN`-tweaked taproot descriptor.
    pub struct Tret {
        tr: Tr<XOnlyPublicKey>,
        tweak: Option<TapretTweak>,
    }

    impl Tret {
        fn with(
            descriptor: Tr<TrackingAccount>,
            derive: impl AsRef<[UnhardenedIndex]>,
            tweak: Option<TapretTweak>,
        ) -> Result<Tret, DeriveError> {
            let tr = Descriptor::Tr(descriptor).derive_descriptor(derive)?;
            Ok(Tret { tr, tweak })
        }
    }

    impl DescriptorTrait<XOnlyPublicKey> for Tret {
        fn sanity_check(&self) -> Result<(), Error> {
            todo!()
        }

        fn address(&self, network: Network) -> Result<Address, Error>
        where
            XOnlyPublicKey: ToPublicKey,
        {
            todo!()
        }

        fn script_pubkey(&self) -> Script
        where
            XOnlyPublicKey: ToPublicKey,
        {
            todo!()
        }

        fn unsigned_script_sig(&self) -> Script
        where
            XOnlyPublicKey: ToPublicKey,
        {
            todo!()
        }

        fn explicit_script(&self) -> Result<Script, Error>
        where
            XOnlyPublicKey: ToPublicKey,
        {
            todo!()
        }

        fn get_satisfaction<S>(&self, satisfier: S) -> Result<(Vec<Vec<u8>>, Script), Error>
        where
            XOnlyPublicKey: ToPublicKey,
            S: Satisfier<XOnlyPublicKey>,
        {
            todo!()
        }

        fn get_satisfaction_mall<S>(&self, satisfier: S) -> Result<(Vec<Vec<u8>>, Script), Error>
        where
            XOnlyPublicKey: ToPublicKey,
            S: Satisfier<XOnlyPublicKey>,
        {
            todo!()
        }

        fn max_satisfaction_weight(&self) -> Result<usize, Error> {
            todo!()
        }

        fn script_code(&self) -> Result<Script, Error>
        where
            XOnlyPublicKey: ToPublicKey,
        {
            todo!()
        }
    }
}
pub use ms::*;
