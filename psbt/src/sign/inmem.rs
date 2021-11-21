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

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::hash::Hasher;

use bitcoin::schnorr::KeyPair;
use bitcoin::secp256k1::{
    schnorrsig as bip340, PublicKey, Secp256k1, SecretKey, Signing,
};
use bitcoin::util::bip32::{
    DerivationPath, ExtendedPrivKey, ExtendedPubKey, Fingerprint,
};
use bitcoin::XpubIdentifier;

use super::{KeyProvider, KeyProviderError};

/// Account-specific extended private key, kept in memory with information about
/// account path derivation from the master key.
///
/// Accounts are uniquially identified by a [`XpubIdentifier`] generated from
/// an extended public key correcponding to the account-level extended private
/// key (i.e. not master extended key, but a key at account-level derivation
/// path).
#[derive(Clone, Eq, PartialEq, Getters, Debug, Display)]
#[display("m[{master_id}]/{derivation}=[{account_xpub}]")]
pub struct MemorySigningAccount {
    #[getter(skip, as_copy)]
    master_id: XpubIdentifier,
    derivation: DerivationPath,
    #[getter(skip)]
    account_xpriv: ExtendedPrivKey,
    account_xpub: ExtendedPubKey,
}

impl Ord for MemorySigningAccount {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.account_xpub.cmp(&other.account_xpub)
    }
}

impl PartialOrd for MemorySigningAccount {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

impl std::hash::Hash for MemorySigningAccount {
    fn hash<H: Hasher>(&self, state: &mut H) { self.account_xpub.hash(state) }
}

impl MemorySigningAccount {
    #[inline]
    pub fn with<C: Signing>(
        secp: &Secp256k1<C>,
        master_id: XpubIdentifier,
        derivation: DerivationPath,
        account_xpriv: ExtendedPrivKey,
    ) -> MemorySigningAccount {
        MemorySigningAccount {
            master_id,
            derivation,
            account_xpriv,
            account_xpub: ExtendedPubKey::from_private(secp, &account_xpriv),
        }
    }

    #[inline]
    pub fn master_fingerprint(&self) -> Fingerprint {
        todo!(
            "Requires convertor from XpubIdentifier to Fingerprint in \
             rust-bitcoin"
        )
    }

    #[inline]
    pub fn account_id(&self) -> XpubIdentifier {
        self.account_xpub.identifier()
    }

    #[inline]
    pub fn account_fingerprint(&self) -> Fingerprint {
        self.account_xpub.fingerprint()
    }

    #[inline]
    pub fn derive_seckey<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        derivation: &DerivationPath,
    ) -> SecretKey {
        let xpriv = self
            .account_xpriv
            .derive_priv(secp, derivation)
            .expect("ExtendedPrivKey integrity issue");
        xpriv.private_key.key
    }

    #[inline]
    pub fn derive_keypair<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        derivation: &DerivationPath,
    ) -> bip340::KeyPair {
        bip340::KeyPair::from_secret_key(
            secp,
            self.derive_seckey(secp, derivation),
        )
    }
}

/// Provider of signing keys which uses memory storage for extended
/// account-specific private keys.
#[derive(Debug)]
pub struct MemoryKeyProvider<'secp, C>
where
    C: Signing,
{
    accounts: BTreeSet<MemorySigningAccount>,
    secp: &'secp Secp256k1<C>,
}

impl<'secp, C> MemoryKeyProvider<'secp, C>
where
    C: Signing,
{
    pub fn with(secp: &'secp Secp256k1<C>) -> Self {
        Self {
            accounts: default!(),
            secp,
        }
    }

    #[inline]
    pub fn add_account(&mut self, account: MemorySigningAccount) -> bool {
        self.accounts.insert(account)
    }
}

impl<'secp, C> IntoIterator for &'secp MemoryKeyProvider<'secp, C>
where
    C: Signing,
{
    type Item = &'secp MemorySigningAccount;
    type IntoIter =
        std::collections::btree_set::Iter<'secp, MemorySigningAccount>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter { self.accounts.iter() }
}

impl<'secp, C> KeyProvider<C> for MemoryKeyProvider<'secp, C>
where
    C: Signing,
{
    #[inline]
    fn secp_context(&self) -> &Secp256k1<C> { &self.secp }

    fn secret_key(
        &self,
        fingerprint: Fingerprint,
        derivation: &DerivationPath,
        pubkey: PublicKey,
    ) -> Result<SecretKey, KeyProviderError> {
        for account in &self.accounts {
            let derivation = if account.account_fingerprint() == fingerprint {
                derivation.clone()
            } else if account.master_fingerprint() == fingerprint {
                let mut iter = derivation.into_iter();
                let remaining_derivation = account
                    .derivation
                    .into_iter()
                    .skip_while(|child| Some(*child) == iter.next());
                let remaining_derivation =
                    remaining_derivation.cloned().collect();
                if iter.count() > 0 {
                    continue;
                }
                remaining_derivation
            } else {
                continue;
            };
            let seckey = account.derive_seckey(&self.secp, &derivation);
            if PublicKey::from_secret_key(&self.secp, &seckey) != pubkey {
                continue;
            }
            return Ok(seckey);
        }

        Err(KeyProviderError::AccountUnknown(fingerprint, pubkey))
    }

    #[inline]
    fn key_pair(
        &self,
        fingerprint: Fingerprint,
        derivation: &DerivationPath,
        pubkey: PublicKey,
    ) -> Result<KeyPair, KeyProviderError> {
        let seckey = self.secret_key(fingerprint, derivation, pubkey)?;
        Ok(bip340::KeyPair::from_secret_key(&self.secp, seckey))
    }
}
