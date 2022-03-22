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

//! Interfaces for signing PSBTs with key sign providers

// TODO: Add Hash secret provider and hash secret satisfaction

use bitcoin::secp256k1::{KeyPair, PublicKey, Secp256k1, SecretKey, Signing, XOnlyPublicKey};
use bitcoin::util::bip32::{DerivationPath, Fingerprint};

mod inmem;
#[cfg(feature = "miniscript")]
mod signer;

pub use inmem::{MemoryKeyProvider, MemorySigningAccount};
#[cfg(feature = "miniscript")]
pub use signer::{SignAll, SignError, SignInput, SignInputError};

/// Errors returned by secret providers (see [`SecretProvider`])
#[derive(
    Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Error, Display, From
)]
#[display(doc_comments)]
pub enum SecretProviderError {
    /// the account corresponding to the given fingerprint {0} that can
    /// generate public key {1} is unknown to the key provider
    AccountUnknown(Fingerprint, PublicKey),
}

/// Structures extended private keys after their corresponding ids ("account
/// ids") and performs derivation to produce corresponding public keys under a
/// given account
pub trait SecretProvider<C: Signing> {
    /// Returns [`Secp256k1`] context object used by the provider
    fn secp_context(&self) -> &Secp256k1<C>;

    /// Returns secret key matching provided public key by iterating over all
    /// extended private keys having the provided fingerprint.
    ///
    /// # Error
    ///
    /// Errors with [`SecretProviderError::AccountUnknown`] if none of the known
    /// extended private keys has the specified fingerprint _and_ can be
    /// derived with a given path into the provided public key.
    ///
    /// NB: This does not imply that the given key can't be derived from know
    /// extended public keys, but with a differend derivation. I.e. the function
    /// will error just because fingerprint does not match correct extended
    /// public key - or derivation path contains a erorr.
    fn secret_key(
        &self,
        fingerprint: Fingerprint,
        derivation: &DerivationPath,
        pubkey: PublicKey,
    ) -> Result<SecretKey, SecretProviderError>;

    /// Returns BIP-340 key pair matching provided public key by iterating over
    /// all extended private keys having the provided fingerprint.
    ///
    /// # Error
    ///
    /// Errors with [`SecretProviderError::AccountUnknown`] if none of the known
    /// extended private keys has the specified fingerprint _and_ can be
    /// derived with a given path into the provided public key.
    ///
    /// NB: This does not imply that the given key can't be derived from know
    /// extended public keys, but with a differend derivation. I.e. the function
    /// will error just because fingerprint does not match correct extended
    /// public key - or derivation path contains a erorr.
    fn key_pair(
        &self,
        fingerprint: Fingerprint,
        derivation: &DerivationPath,
        pubkey: XOnlyPublicKey,
    ) -> Result<KeyPair, SecretProviderError>;

    /// Returns whether keys returned by this provider can be used for creating
    /// aggregated Schnorr signatures.
    fn use_musig(&self) -> bool;
}
