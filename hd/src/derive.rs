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

use std::cell::Cell;

use bitcoin::secp256k1::{Secp256k1, Verification};
use bitcoin::{Address, Network, PublicKey, Script};
use miniscript::{
    Descriptor, DescriptorTrait, ForEach, ForEachKey, TranslatePk2,
};

use crate::{PubkeyChain, UnhardenedIndex};

/// Errors during descriptor derivation
#[derive(
    Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error
)]
#[display(doc_comments)]
pub enum DeriveError {
    /// account-level extended public in the descriptor has different network
    /// requirements
    InconsistentKeyNetwork,
    /// key derivation in the descriptor uses inconsistent wildcard pattern
    InconsistentKeyDerivePattern,
    /// the provided derive pattern does not match descriptor derivation
    /// wildcard
    DerivePatternMismatch,
    /// descriptor contains no keys; corresponding outputs will be
    /// "anyone-can-sped"
    NoKeys,
    /// descriptor does not support address generation
    NoAddressForDescriptor,
}

/// Methods for deriving from output descriptor
pub trait DescriptorDerive {
    /// Check sanity of the output descriptor (see [`DeriveError`] for the list
    /// of possible inconsistencies).
    fn check_sanity(&self) -> Result<(), DeriveError>;

    /// Measure length of the derivation wildcard pattern accross all keys
    /// participating descriptor
    fn derive_pattern_len(&self) -> Result<usize, DeriveError>;

    /// Detect bitcoin network which should be used with the provided descriptor
    fn network(&self) -> Result<Network, DeriveError>;

    /// Translate descriptor to a specifically-derived form
    fn derive<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        pat: impl AsRef<[UnhardenedIndex]>,
    ) -> Result<Descriptor<PublicKey>, DeriveError>;

    /// Create scriptPubkey for specific derive pattern
    fn script_pubkey<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        pat: impl AsRef<[UnhardenedIndex]>,
    ) -> Result<Script, DeriveError>;

    /// Generate address from the descriptor for specific derive pattern
    fn address<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        pat: impl AsRef<[UnhardenedIndex]>,
    ) -> Result<Address, DeriveError>;
}

impl DescriptorDerive for miniscript::Descriptor<PubkeyChain> {
    #[inline]
    fn check_sanity(&self) -> Result<(), DeriveError> {
        self.derive_pattern_len()?;
        self.network()?;
        Ok(())
    }

    fn derive_pattern_len(&self) -> Result<usize, DeriveError> {
        let len = Cell::new(None);
        self.for_each_key(|key| {
            let c = match key {
                ForEach::Key(pubkeychain) => pubkeychain
                    .terminal_path
                    .iter()
                    .filter(|step| step.is_wildcard())
                    .count(),
                ForEach::Hash(_) => {
                    unreachable!("pubkeychain hash is not equal to itself")
                }
            };
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
        self.for_each_key(|key| {
            let net = match key {
                ForEach::Key(pubkeychain) => pubkeychain.branch_xpub.network,
                ForEach::Hash(_) => {
                    unreachable!("pubkeychain hash is not equal to itself")
                }
            };
            match (network.get(), net) {
                (None, net) => {
                    network.set(Some(net));
                    true
                }
                (Some(net1), net2) if net1 != net2 => false,
                _ => true,
            }
        });
        network.get().ok_or(DeriveError::NoKeys)
    }

    fn derive<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        pat: impl AsRef<[UnhardenedIndex]>,
    ) -> Result<Descriptor<PublicKey>, DeriveError> {
        let pat = pat.as_ref();
        if pat.len() != self.derive_pattern_len()? {
            return Err(DeriveError::DerivePatternMismatch);
        }
        Ok(self.translate_pk2_infallible(|pubkeychain| {
            pubkeychain.derive_pubkey(secp, |index| pat[index])
        }))
    }

    #[inline]
    fn script_pubkey<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        pat: impl AsRef<[UnhardenedIndex]>,
    ) -> Result<Script, DeriveError> {
        let d = self.derive(secp, pat)?;
        Ok(DescriptorTrait::script_pubkey(&d))
    }

    #[inline]
    fn address<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        pat: impl AsRef<[UnhardenedIndex]>,
    ) -> Result<Address, DeriveError> {
        let network = self.network()?;
        let spk = DescriptorDerive::script_pubkey(self, secp, pat)?;
        Address::from_script(&spk, network)
            .ok_or(DeriveError::NoAddressForDescriptor)
    }
}
