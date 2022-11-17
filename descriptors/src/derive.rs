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

use bitcoin::secp256k1::{Secp256k1, Verification};
use bitcoin::{Address, Network, Script};

use bitcoin_hd::{DerivationAccount, DeriveError, DerivePatternError, UnhardenedIndex};

#[cfg(not(feature = "miniscript"))]
pub mod miniscript {
    #[derive(
        Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error
    )]
    #[display(Debug)]
    pub enum Error {}
}

/// Methods for deriving from output descriptor.
pub trait DeriveDescriptor<Key> {
    /// Generated descriptor type as an output from
    /// [`DeriveDescriptor::derive_descriptor`].
    type Output;

    /// Translates descriptor to a specifically-derived form.
    fn derive_descriptor<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        pat: impl AsRef<[UnhardenedIndex]>,
    ) -> Result<Self::Output, DeriveError>;
}

/// Standard methods which should be supported by descriptors of different
/// sorts.
pub trait Descriptor<Key> {
    /// Checks sanity of the output descriptor (see [`DeriveError`] for the list
    /// of possible inconsistencies).
    fn check_sanity(&self) -> Result<(), DeriveError>;

    /// Measures length of the derivation wildcard pattern accross all keys
    /// participating descriptor
    fn derive_pattern_len(&self) -> Result<usize, DeriveError>;

    /// Detects bitcoin network which should be used with the provided
    /// descriptor
    fn network(&self) -> Result<Network, DeriveError>;

    /// Generates address from the descriptor for specific derive pattern
    fn address<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        pat: impl AsRef<[UnhardenedIndex]>,
    ) -> Result<Address, DeriveError>;

    /// Creates scriptPubkey for specific derive pattern in pre-taproot descriptors
    fn script_pubkey_pretr<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        pat: impl AsRef<[UnhardenedIndex]>,
    ) -> Result<Script, DeriveError>;

    /// Creates scriptPubkey for specific derive pattern in taproot descriptors
    fn script_pubkey_tr<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        pat: impl AsRef<[UnhardenedIndex]>,
    ) -> Result<Script, DeriveError>;
}

#[cfg(feature = "miniscript")]
mod ms {
    use std::cell::Cell;
    use bitcoin::XOnlyPublicKey;

    use miniscript::{ForEachKey, translate_hash_fail, TranslatePk, Translator};
    use bitcoin_hd::{DeriveError, SegmentIndexes};
    use bitcoin_hd::account::DerivePublicKey;

    use super::*;

    struct KeyTranslator<'a, C: Verification> {
        secp: &'a Secp256k1<C>,
        pat: &'a [UnhardenedIndex]
    }

    impl<'a, C> Translator<DerivationAccount, bitcoin::PublicKey, DerivePatternError> for KeyTranslator<'a, C>
        where
            C: Verification
    {
        fn pk(&mut self, pk: &DerivationAccount) -> Result<bitcoin::PublicKey, DerivePatternError> {
            pk.derive_public_key(&self.secp, self.pat)
                .map(bitcoin::PublicKey::new)
        }

        translate_hash_fail!(DerivationAccount, bitcoin::PublicKey, DerivePatternError);
    }

    impl<'a, C> Translator<DerivationAccount, XOnlyPublicKey, DerivePatternError> for KeyTranslator<'a, C>
        where
            C: Verification
    {
        fn pk(&mut self, pk: &DerivationAccount) -> Result<XOnlyPublicKey, DerivePatternError> {
            pk.derive_public_key(&self.secp, self.pat)
                .map(XOnlyPublicKey::from)
        }

        translate_hash_fail!(DerivationAccount, XOnlyPublicKey, DerivePatternError);
    }

    impl DeriveDescriptor<bitcoin::PublicKey> for miniscript::Descriptor<DerivationAccount>
    where
        Self: TranslatePk<DerivationAccount, bitcoin::PublicKey>,
    {
        type Output = miniscript::Descriptor<bitcoin::PublicKey>;

        fn derive_descriptor<C: Verification>(
            &self,
            secp: &Secp256k1<C>,
            pat: impl AsRef<[UnhardenedIndex]>,
        ) -> Result<miniscript::Descriptor<bitcoin::PublicKey>, DeriveError> {
            let pat = pat.as_ref();
            if pat.len() != self.derive_pattern_len()? {
                return Err(DeriveError::DerivePatternMismatch);
            }
            let mut translator = KeyTranslator { secp, pat };
            <miniscript::Descriptor<DerivationAccount> as TranslatePk<_, bitcoin::PublicKey>>::translate_pk(self, &mut translator)
                .map_err(DeriveError::from)
        }
    }

    impl DeriveDescriptor<XOnlyPublicKey> for miniscript::Descriptor<DerivationAccount>
        where
            Self: TranslatePk<DerivationAccount, XOnlyPublicKey>,
    {
        type Output = miniscript::Descriptor<XOnlyPublicKey>;

        fn derive_descriptor<C: Verification>(
            &self,
            secp: &Secp256k1<C>,
            pat: impl AsRef<[UnhardenedIndex]>,
        ) -> Result<miniscript::Descriptor<XOnlyPublicKey>, DeriveError> {
            let pat = pat.as_ref();
            if pat.len() != self.derive_pattern_len()? {
                return Err(DeriveError::DerivePatternMismatch);
            }
            let mut translator = KeyTranslator { secp, pat };
            <miniscript::Descriptor<DerivationAccount> as TranslatePk<_, XOnlyPublicKey>>::translate_pk(self, &mut translator)
                .map_err(DeriveError::from)
        }
    }

    impl Descriptor<DerivationAccount> for miniscript::Descriptor<DerivationAccount>
    {
        #[inline]
        fn check_sanity(&self) -> Result<(), DeriveError> {
            self.derive_pattern_len()?;
            self.network()?;
            Ok(())
        }

        fn derive_pattern_len(&self) -> Result<usize, DeriveError> {
            let len = Cell::new(None);
            self.for_each_key(|key| {
                let c = key
                    .terminal_path
                    .iter()
                    .filter(|step| step.count() > 1)
                    .count();
                match (len.get(), c) {
                    (None, c) => {
                        len.set(Some(c));
                        true
                    }
                    (Some(c1), c2) if c1 != c2 => false,
                    _ => true,
                }
            });
            len.get().ok_or(DeriveError::NoKeys)
        }

        fn network(&self) -> Result<Network, DeriveError> {
            let network = Cell::new(None);
            self.for_each_key(
                |key| match (network.get(), key.account_xpub.network) {
                    (None, net) => {
                        network.set(Some(net));
                        true
                    }
                    (Some(net1), net2) if net1 != net2 => false,
                    _ => true,
                },
            );
            network.get().ok_or(DeriveError::NoKeys)
        }

        #[inline]
        fn address<C: Verification>(
            &self,
            secp: &Secp256k1<C>,
            pat: impl AsRef<[UnhardenedIndex]>,
        ) -> Result<Address, DeriveError> {
            let network = self.network()?;
            let spk = Descriptor::script_pubkey_pretr(self, secp, pat)?;
            Address::from_script(&spk, network).map_err(|_| DeriveError::NoAddressForDescriptor)
        }

        #[inline]
        fn script_pubkey_pretr<C: Verification>(
            &self,
            secp: &Secp256k1<C>,
            pat: impl AsRef<[UnhardenedIndex]>,
        ) -> Result<Script, DeriveError> {
            let d = <Self as DeriveDescriptor<bitcoin::PublicKey>>::derive_descriptor(self, secp, pat)?;
            Ok(d.script_pubkey())
        }

        #[inline]
        fn script_pubkey_tr<C: Verification>(
            &self,
            secp: &Secp256k1<C>,
            pat: impl AsRef<[UnhardenedIndex]>,
        ) -> Result<Script, DeriveError> {
            let d = <Self as DeriveDescriptor<XOnlyPublicKey>>::derive_descriptor(self, secp, pat)?;
            Ok(d.script_pubkey())
        }
    }
}
