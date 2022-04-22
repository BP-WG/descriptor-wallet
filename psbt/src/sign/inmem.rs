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

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::hash::Hasher;

use bitcoin::secp256k1::{KeyPair, PublicKey, Secp256k1, SecretKey, Signing, XOnlyPublicKey};
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey, Fingerprint};
use bitcoin::XpubIdentifier;
#[cfg(feature = "miniscript")]
use bitcoin_hd::Bip43;
use bitcoin_hd::{AccountStep, DerivationStandard, TerminalStep, TrackingAccount, XpubRef};
#[cfg(feature = "miniscript")]
use miniscript::Descriptor;

use super::{SecretProvider, SecretProviderError};

/// Account-specific extended private key, kept in memory with information about
/// account path derivation from the master key.
///
/// Accounts are uniquially identified by a [`XpubIdentifier`] generated from
/// an extended public key corresponding to the account-level extended private
/// key (i.e. not master extended key, but a key at account-level derivation
/// path).
#[derive(Clone, Getters, Debug, Display)]
#[display("m[{master_id}]/{derivation}=[{account_xpub}]")]
pub struct MemorySigningAccount {
    master_id: XpubIdentifier,
    derivation: DerivationPath,
    account_xpriv: ExtendedPrivKey,
    account_xpub: ExtendedPubKey,
}

impl Ord for MemorySigningAccount {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering { self.account_xpub.cmp(&other.account_xpub) }
}

impl PartialOrd for MemorySigningAccount {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl PartialEq for MemorySigningAccount {
    fn eq(&self, other: &Self) -> bool { self.account_xpub == other.account_xpub }
}

impl Eq for MemorySigningAccount {}

impl std::hash::Hash for MemorySigningAccount {
    fn hash<H: Hasher>(&self, state: &mut H) { self.account_xpub.hash(state) }
}

impl MemorySigningAccount {
    #[inline]
    pub fn with<C: Signing>(
        secp: &Secp256k1<C>,
        master_id: XpubIdentifier,
        derivation: impl Into<DerivationPath>,
        account_xpriv: ExtendedPrivKey,
    ) -> MemorySigningAccount {
        MemorySigningAccount {
            master_id,
            derivation: derivation.into(),
            account_xpriv,
            account_xpub: ExtendedPubKey::from_priv(secp, &account_xpriv),
        }
    }

    #[inline]
    pub fn master_fingerprint(&self) -> Fingerprint {
        Fingerprint::from(&self.master_id[..4])
        // TODO: Do a convertor from XpubIdentifier to Fingerprint in
        //       rust-bitcoin
    }

    #[inline]
    pub fn account_id(&self) -> XpubIdentifier { self.account_xpub.identifier() }

    #[inline]
    pub fn account_fingerprint(&self) -> Fingerprint { self.account_xpub.fingerprint() }

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
        xpriv.private_key
    }

    #[inline]
    pub fn derive_keypair<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        derivation: &DerivationPath,
    ) -> KeyPair {
        KeyPair::from_secret_key(secp, self.derive_seckey(secp, derivation))
    }

    #[inline]
    pub fn to_account(&self) -> TrackingAccount {
        TrackingAccount {
            seed_based: true,
            master: XpubRef::Fingerprint(self.master_fingerprint()),
            account_path: self
                .derivation
                .into_iter()
                .copied()
                .map(AccountStep::try_from)
                .collect::<Result<_, _>>()
                .expect("ChildNumber is broken"),
            account_xpub: self.account_xpub,
            revocation_seal: None,
            terminal_path: vec![TerminalStep::Wildcard, TerminalStep::Wildcard],
        }
    }

    #[cfg(feature = "miniscript")]
    pub fn recommended_descriptor(&self) -> Option<Descriptor<TrackingAccount>> {
        let account = self.to_account();
        Some(match Bip43::deduce(&self.derivation)? {
            Bip43::Bip44 => Descriptor::new_pkh(account),
            Bip43::Bip84 => Descriptor::new_wpkh(account).expect("miniscript descriptors broken"),
            Bip43::Bip49 => {
                Descriptor::new_sh_wpkh(account).expect("miniscript descriptors broken")
            }
            Bip43::Bip86 => {
                Descriptor::new_tr(account, None).expect("miniscript descriptors broken")
            }
            Bip43::Bip45 => Descriptor::new_sh_sortedmulti(1, vec![account])
                .expect("miniscript descriptors broken"),
            Bip43::Bip48Nested => Descriptor::new_sh_sortedmulti(1, vec![account])
                .expect("miniscript descriptors broken"),
            Bip43::Bip87 => Descriptor::new_sh_wsh_sortedmulti(1, vec![account])
                .expect("miniscript descriptors broken"),
            _ => return None,
        })
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
    /// Participate keys from this provider in musigs
    musig: bool,
}

impl<'secp, C> MemoryKeyProvider<'secp, C>
where
    C: Signing,
{
    pub fn with(secp: &'secp Secp256k1<C>, musig: bool) -> Self {
        Self {
            accounts: default!(),
            secp,
            musig,
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
    type IntoIter = std::collections::btree_set::Iter<'secp, MemorySigningAccount>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter { self.accounts.iter() }
}

impl<'secp, C> SecretProvider<C> for MemoryKeyProvider<'secp, C>
where
    C: Signing,
{
    #[inline]
    fn secp_context(&self) -> &Secp256k1<C> { self.secp }

    fn secret_key(
        &self,
        fingerprint: Fingerprint,
        derivation: &DerivationPath,
        pubkey: PublicKey,
    ) -> Result<SecretKey, SecretProviderError> {
        for account in &self.accounts {
            let derivation = if account.account_fingerprint() == fingerprint {
                derivation.clone()
            } else if account.master_fingerprint() == fingerprint {
                let mut iter = account.derivation.into_iter();
                let remaining_derivation = derivation
                    .into_iter()
                    .skip_while(|child| Some(*child) == iter.next());
                let remaining_derivation = remaining_derivation.cloned().collect();
                if iter.count() > 0 {
                    continue;
                }
                remaining_derivation
            } else {
                continue;
            };
            let seckey = account.derive_seckey(self.secp, &derivation);
            // We need to skip party flag
            if PublicKey::from_secret_key(self.secp, &seckey).serialize()[1..]
                != pubkey.serialize()[1..]
            {
                continue;
            }
            return Ok(seckey);
        }

        Err(SecretProviderError::AccountUnknown(fingerprint, pubkey))
    }

    #[inline]
    fn key_pair(
        &self,
        fingerprint: Fingerprint,
        derivation: &DerivationPath,
        pubkey: XOnlyPublicKey,
    ) -> Result<KeyPair, SecretProviderError> {
        let mut data: Vec<u8> = vec![0x02];
        data.extend(pubkey.serialize().iter());
        let pk = PublicKey::from_slice(&data).expect("fixed size slice");
        let seckey = self.secret_key(fingerprint, derivation, pk)?;
        Ok(KeyPair::from_secret_key(self.secp, seckey))
    }

    #[inline]
    fn use_musig(&self) -> bool { self.musig }
}
