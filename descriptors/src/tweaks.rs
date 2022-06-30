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

use core::fmt::{self, Display, Formatter};

use bitcoin::hashes::sha256;
use bitcoin::secp256k1;

/// Keeps tweak information on all kinds of transaction output tweaks required
/// for the wallet to reconstruct actual `scriptPubkeys` for the given wallet
/// descriptor.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display(inner)]
pub enum OutputTweak {
    TapReturn(TapretTweak),
    P2cKey(PubkeyTweak),
    P2cScript(ScriptTweak),
}

/// Information about tapret output tweaks.
///
/// Required for the wallet to reconstruct actual `scriptPubkeys` for the given
/// wallet descriptor.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display(inner)]
pub struct TapretTweak(sha256::Hash);

/// Information about pay-to-contract output tweaks applied to single-key based
/// outputs (P2PK, P2PKH, P2WPKH, P2WPKH-in-P2SH).
///
/// Required for the wallet to reconstruct actual `scriptPubkeys` for the given
/// wallet descriptor.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display(display_secret)]
pub struct PubkeyTweak(secp256k1::SecretKey);

fn display_secret<T>(secret: &T) -> String
where
    T: Display,
{
    secret.to_string()
}

/// Information about pay-to-contract output tweaks embedded into script-based
/// outputs (bare scripts, P2SH, P2WSH, P2WSH-in-P2SH).
///
/// Required for the wallet to reconstruct actual `scriptPubkeys` for the given
/// wallet descriptor.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
// TODO: Generalize the structure to support multiple script tweaks
pub struct ScriptTweak {
    pub tweak: secp256k1::SecretKey,
    pub original_key: bitcoin::PublicKey,
}

impl Display for ScriptTweak {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.tweak.display_secret(), self.original_key)
    }
}

#[cfg(feature = "miniscript")]
mod ms {
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{Address, Network, Script, XOnlyPublicKey};
    use bitcoin_hd::{DeriveDescriptor, DeriveError, TrackingAccount, UnhardenedIndex};
    use miniscript::{descriptor, DescriptorTrait, Error, Satisfier, ToPublicKey};

    use super::*;

    /// `OP_RETURN`-tweaked taproot descriptor.
    #[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
    #[derive(StrictEncode, StrictDecode)]
    #[cfg_attr(
        feature = "serde",
        derive(Serialize, Deserialize),
        serde(crate = "serde_crate")
    )]
    pub struct Tret {
        #[cfg_attr(feature = "serde", serde(with = "serde_with::rust::display_fromstr"))]
        tr: descriptor::Tr<XOnlyPublicKey>,
        tweak: Option<TapretTweak>,
    }

    impl Tret {
        pub fn with<C: secp256k1::Verification>(
            secp: &Secp256k1<C>,
            descriptor: descriptor::Tr<TrackingAccount>,
            derive: impl AsRef<[UnhardenedIndex]>,
            tweak: Option<TapretTweak>,
        ) -> Result<Tret, DeriveError> {
            let tr =
                DeriveDescriptor::<XOnlyPublicKey>::derive_descriptor(&descriptor, secp, derive)?;
            Ok(Tret { tr, tweak })
        }
    }

    #[allow(unused_variables)]
    impl DescriptorTrait<XOnlyPublicKey> for Tret {
        fn sanity_check(&self) -> Result<(), Error> { todo!() }

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

        fn max_satisfaction_weight(&self) -> Result<usize, Error> { todo!() }

        fn script_code(&self) -> Result<Script, Error>
        where
            XOnlyPublicKey: ToPublicKey,
        {
            todo!()
        }
    }
}
#[cfg(feature = "miniscript")]
pub use ms::*;
