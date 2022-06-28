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

// In the future this mod will probably become part of Miniscript library

use std::collections::BTreeSet;

use bitcoin::hashes::hash160;
use miniscript::miniscript::iter::PkPkh;
use miniscript::{Miniscript, MiniscriptKey, ToPublicKey, TranslatePk, TranslatePk1};

use super::LockScript;

// TODO #17: Derive more traits when `miniscript::Error` type do that
/// Errors that may happen during LockScript parsing process
#[derive(Debug, Display, Error)]
#[display(doc_comments)]
pub enum PubkeyParseError {
    /// Unexpected pubkey hash when enumerating in "keys only" mode
    PubkeyHash(hash160::Hash),

    /// Miniscript-level error
    Miniscript(miniscript::Error),
}

impl From<miniscript::Error> for PubkeyParseError {
    fn from(miniscript_error: miniscript::Error) -> Self { Self::Miniscript(miniscript_error) }
}

#[allow(type_alias_bounds)] // Without them associated type does not work
type KeySets<Ctx: miniscript::ScriptContext> = (
    BTreeSet<Ctx::Key>,
    BTreeSet<<Ctx::Key as MiniscriptKey>::Hash>,
);
#[allow(type_alias_bounds)] // Without them associated type does not work
type KeyLists<Ctx: miniscript::ScriptContext> =
    (Vec<Ctx::Key>, Vec<<Ctx::Key as MiniscriptKey>::Hash>);

impl LockScript {
    /// Returns set of unique public keys from the script; fails on public key
    /// hash
    pub fn extract_pubkeyset<Ctx>(&self) -> Result<BTreeSet<Ctx::Key>, PubkeyParseError>
    where
        Ctx: miniscript::ScriptContext,
        Ctx::Key: ToPublicKey,
    {
        Ok(BTreeSet::from_iter(self.extract_pubkeys::<Ctx>()?))
    }

    /// Returns tuple of two sets: one for unique public keys and one for
    /// unique hash values, extracted from the script
    pub fn extract_pubkey_hash_set<Ctx>(&self) -> Result<KeySets<Ctx>, PubkeyParseError>
    where
        Ctx: miniscript::ScriptContext,
        Ctx::Key: ToPublicKey,
    {
        let (keys, hashes) = self.extract_pubkeys_and_hashes::<Ctx>()?;
        Ok((BTreeSet::from_iter(keys), BTreeSet::from_iter(hashes)))
    }

    /// Returns tuple with two vectors: one for public keys and one for public
    /// key hashes present in the script; if any of the keys or hashes has more
    /// than a single occurrence it returns all occurrences for each of them
    pub fn extract_pubkeys_and_hashes<Ctx>(&self) -> Result<KeyLists<Ctx>, PubkeyParseError>
    where
        Ctx: miniscript::ScriptContext,
        Ctx::Key: ToPublicKey,
    {
        Miniscript::<Ctx::Key, Ctx>::parse_insane(&*self.clone())?
            .iter_pk_pkh()
            .try_fold(
                (
                    Vec::<Ctx::Key>::new(),
                    Vec::<<Ctx::Key as MiniscriptKey>::Hash>::new(),
                ),
                |(mut keys, mut hashes), item| {
                    match item {
                        PkPkh::HashedPubkey(hash) => hashes.push(hash),
                        PkPkh::PlainPubkey(key) => keys.push(key),
                    }
                    Ok((keys, hashes))
                },
            )
    }

    /// Returns all public keys found in the script; fails on public key hash.
    /// If the key present multiple times in the script it returns all
    /// occurrences.
    pub fn extract_pubkeys<Ctx>(&self) -> Result<Vec<Ctx::Key>, PubkeyParseError>
    where
        Ctx: miniscript::ScriptContext,
        Ctx::Key: ToPublicKey,
    {
        Miniscript::<Ctx::Key, Ctx>::parse(&*self.clone())?
            .iter_pk_pkh()
            .try_fold(Vec::<Ctx::Key>::new(), |mut keys, item| match item {
                PkPkh::HashedPubkey(hash) => Err(PubkeyParseError::PubkeyHash(hash)),
                PkPkh::PlainPubkey(key) => {
                    keys.push(key);
                    Ok(keys)
                }
            })
    }

    /// Replaces pubkeys using provided matching function; does not fail on
    /// public key hashes.
    pub fn replace_pubkeys<Ctx, Fpk>(&self, processor: Fpk) -> Result<Self, PubkeyParseError>
    where
        Ctx: miniscript::ScriptContext,
        Ctx::Key: ToPublicKey,
        Fpk: Fn(&Ctx::Key) -> Ctx::Key,
    {
        let ms = Miniscript::<Ctx::Key, Ctx>::parse(&*self.clone())?;
        if let Some(hash) = ms.iter_pkh().collect::<Vec<_>>().first() {
            return Err(PubkeyParseError::PubkeyHash(*hash));
        }
        let result = ms.translate_pk1_infallible(processor);
        Ok(LockScript::from(result.encode()))
    }

    /// Replaces public keys and public key hashes using provided matching
    /// functions.
    pub fn replace_pubkeys_and_hashes<Ctx, Fpk, Fpkh>(
        &self,
        key_processor: Fpk,
        hash_processor: Fpkh,
    ) -> Result<Self, PubkeyParseError>
    where
        Ctx: miniscript::ScriptContext<Key = bitcoin::PublicKey>,
        Fpk: Fn(&Ctx::Key) -> Ctx::Key,
        Fpkh: Fn(&<Ctx::Key as MiniscriptKey>::Hash) -> <Ctx::Key as MiniscriptKey>::Hash,
    {
        let result = Miniscript::<Ctx::Key, Ctx>::parse(&*self.clone())?
            .translate_pk_infallible(key_processor, hash_processor);
        Ok(LockScript::from(result.encode()))
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::str::FromStr;

    use bitcoin::hashes::{hash160, sha256, Hash};
    use bitcoin::{PubkeyHash, PublicKey};
    use miniscript::Segwitv0;

    use super::*;

    macro_rules! ms_str {
        ($($arg:tt)*) => (LockScript::from(Miniscript::<bitcoin::PublicKey, Segwitv0>::from_str_insane(&format!($($arg)*)).unwrap().encode()))
    }

    macro_rules! policy_str {
        ($($arg:tt)*) => (LockScript::from(miniscript::policy::Concrete::<bitcoin::PublicKey>::from_str(&format!($($arg)*)).unwrap().compile::<Segwitv0>().unwrap().encode()))
    }

    pub(crate) fn gen_secp_pubkeys(n: usize) -> Vec<secp256k1::PublicKey> {
        let mut ret = Vec::with_capacity(n);
        let mut sk = [0; 32];

        for i in 1..n + 1 {
            sk[0] = i as u8;
            sk[1] = (i >> 8) as u8;
            sk[2] = (i >> 16) as u8;

            ret.push(secp256k1::PublicKey::from_secret_key(
                secp256k1::SECP256K1,
                &secp256k1::SecretKey::from_slice(&sk[..]).unwrap(),
            ));
        }
        ret
    }

    pub(crate) fn gen_bitcoin_pubkeys(n: usize, compressed: bool) -> Vec<bitcoin::PublicKey> {
        gen_secp_pubkeys(n)
            .into_iter()
            .map(|inner| bitcoin::PublicKey { inner, compressed })
            .collect()
    }

    pub(crate) fn gen_pubkeys_and_hashes(n: usize) -> (Vec<PublicKey>, Vec<PubkeyHash>) {
        let pks = gen_bitcoin_pubkeys(n, true);
        let pkhs = pks.iter().map(PublicKey::pubkey_hash).collect();
        (pks, pkhs)
    }

    pub(crate) fn no_keys_or_hashes_suite(proc: fn(LockScript) -> ()) {
        let sha_hash = sha256::Hash::hash("(nearly)random string".as_bytes());
        let dummy_hashes: Vec<hash160::Hash> = (1..13)
            .map(|i| hash160::Hash::from_inner([i; 20]))
            .collect();

        proc(ms_str!("older(921)"));
        proc(ms_str!("sha256({})", sha_hash));
        proc(ms_str!("hash256({})", sha_hash));
        proc(ms_str!("hash160({})", dummy_hashes[0]));
        proc(ms_str!("ripemd160({})", dummy_hashes[1]));
        proc(ms_str!("hash160({})", dummy_hashes[2]));
    }

    pub(crate) fn single_key_suite(proc: fn(LockScript, bitcoin::PublicKey) -> ()) {
        let (keys, _) = gen_pubkeys_and_hashes(6);
        proc(ms_str!("c:pk_k({})", keys[1]), keys[1]);
        proc(ms_str!("c:pk_k({})", keys[2]), keys[2]);
        proc(ms_str!("c:pk_k({})", keys[3]), keys[3]);
        proc(ms_str!("c:pk_k({})", keys[0]), keys[0]);
    }

    pub(crate) fn single_unmatched_key_suite(proc: fn(LockScript, bitcoin::PublicKey) -> ()) {
        let (keys, _) = gen_pubkeys_and_hashes(6);
        proc(ms_str!("c:pk_k({})", keys[1]), keys[0]);
        proc(ms_str!("c:pk_k({})", keys[2]), keys[3]);
        proc(ms_str!("c:pk_k({})", keys[3]), keys[4]);
        proc(ms_str!("c:pk_k({})", keys[4]), keys[1]);
    }

    pub(crate) fn single_keyhash_suite(proc: fn(LockScript, PubkeyHash) -> ()) {
        let (_, hashes) = gen_pubkeys_and_hashes(6);
        proc(ms_str!("c:pk_h({})", hashes[1]), hashes[1]);
        proc(ms_str!("c:pk_h({})", hashes[2]), hashes[2]);
        proc(ms_str!("c:pk_h({})", hashes[3]), hashes[3]);
        proc(ms_str!("c:pk_h({})", hashes[0]), hashes[0]);
    }

    pub(crate) fn single_unmatched_keyhash_suite(proc: fn(LockScript, PubkeyHash) -> ()) {
        let (_, hashes) = gen_pubkeys_and_hashes(6);
        proc(ms_str!("c:pk_h({})", hashes[1]), hashes[0]);
        proc(ms_str!("c:pk_h({})", hashes[2]), hashes[3]);
        proc(ms_str!("c:pk_h({})", hashes[3]), hashes[4]);
        proc(ms_str!("c:pk_h({})", hashes[4]), hashes[1]);
    }

    pub(crate) fn complex_keys_suite(proc: fn(LockScript, Vec<bitcoin::PublicKey>) -> ()) {
        let (keys, _) = gen_pubkeys_and_hashes(6);
        proc(
            policy_str!("thresh(2,pk({}),pk({}))", keys[0], keys[1]),
            keys[..2].to_vec(),
        );
        proc(
            policy_str!(
                "thresh(3,pk({}),pk({}),pk({}),pk({}),pk({}))",
                keys[0],
                keys[1],
                keys[2],
                keys[3],
                keys[4]
            ),
            keys[..5].to_vec(),
        );
    }

    pub(crate) fn complex_unmatched_keys_suite(
        proc: fn(LockScript, Vec<bitcoin::PublicKey>) -> (),
    ) {
        let (keys, _) = gen_pubkeys_and_hashes(10);
        proc(
            policy_str!("thresh(2,pk({}),pk({}))", keys[0], keys[1]),
            keys[..5].to_vec(),
        );
        proc(
            policy_str!(
                "thresh(3,pk({}),pk({}),pk({}),pk({}),pk({}))",
                keys[0],
                keys[1],
                keys[2],
                keys[3],
                keys[4]
            ),
            keys[..2].to_vec(),
        );
    }

    pub(crate) fn complex_suite(proc: fn(LockScript, Vec<bitcoin::PublicKey>) -> ()) {
        let (keys, _) = gen_pubkeys_and_hashes(10);
        proc(
            policy_str!(
                "or(thresh(3,pk({}),pk({}),pk({})),and(thresh(2,pk({}),pk({})),older(10000)))",
                keys[0],
                keys[1],
                keys[2],
                keys[3],
                keys[4]
            ),
            vec![keys[3], keys[4], keys[0], keys[1], keys[2]],
        );
        proc(
            policy_str!(
                "or(thresh(3,pk({}),pk({}),pk({})),and(thresh(2,pk({}),pk({})),older(10000)))",
                keys[0],
                keys[1],
                keys[3],
                keys[5],
                keys[4]
            ),
            vec![keys[5], keys[4], keys[0], keys[1], keys[3]],
        );
    }

    #[test]
    #[should_panic(expected = "Miniscript(AnalysisError(SiglessBranch))")]
    fn test_script_parse_no_key() {
        no_keys_or_hashes_suite(|lockscript| {
            assert_eq!(lockscript.extract_pubkeys::<Segwitv0>().unwrap(), vec![]);
            assert_eq!(
                lockscript.extract_pubkey_hash_set::<Segwitv0>().unwrap(),
                (BTreeSet::new(), BTreeSet::new())
            );
        })
    }

    #[test]
    fn test_script_parse_single_key() {
        single_key_suite(|lockscript, pubkey| {
            let extract = lockscript.extract_pubkeys::<Segwitv0>().unwrap();
            assert_eq!(extract[0], pubkey);
            assert_eq!(
                lockscript.extract_pubkey_hash_set::<Segwitv0>().unwrap(),
                (BTreeSet::from_iter(vec![pubkey]), BTreeSet::new())
            );
        });

        single_unmatched_key_suite(|lockscript, pubkey| {
            assert_ne!(lockscript.extract_pubkeys::<Segwitv0>().unwrap(), vec![
                pubkey
            ]);
        });
    }

    #[test]
    fn test_script_parse_singlehash() {
        single_keyhash_suite(|lockscript, hash| {
            if let Err(PubkeyParseError::PubkeyHash(found_hash)) =
                lockscript.extract_pubkeyset::<Segwitv0>()
            {
                assert_eq!(hash, found_hash.into())
            } else {
                panic!("extract_pubkeyset must return error")
            }
            assert_eq!(
                lockscript.extract_pubkey_hash_set::<Segwitv0>().unwrap(),
                (BTreeSet::new(), BTreeSet::from_iter(vec![hash.as_hash()]))
            );
        });

        single_unmatched_keyhash_suite(|lockscript, hash| {
            let (_, hashset) = lockscript.extract_pubkey_hash_set::<Segwitv0>().unwrap();
            assert_ne!(hashset, BTreeSet::from_iter(vec![hash.as_hash()]));
        });
    }

    #[test]
    fn test_script_parse_complex_keys() {
        complex_keys_suite(|lockscript, keys| {
            assert_eq!(lockscript.extract_pubkeys::<Segwitv0>().unwrap(), keys);
            assert_eq!(
                lockscript.extract_pubkey_hash_set::<Segwitv0>().unwrap(),
                (BTreeSet::from_iter(keys), BTreeSet::new())
            );
        });
    }

    #[test]
    fn test_script_parse_complex_unmatched_keys() {
        complex_unmatched_keys_suite(|lockscript, keys| {
            let extract = lockscript.extract_pubkeys::<Segwitv0>().unwrap();
            assert_ne!(extract.len(), 0);
            assert_ne!(extract, keys);
        });
    }

    #[test]
    fn test_script_parse_complex_script() {
        complex_suite(|lockscript, keys| {
            assert_eq!(lockscript.extract_pubkeys::<Segwitv0>().unwrap(), keys);
            assert_eq!(
                lockscript.extract_pubkeyset::<Segwitv0>().unwrap(),
                BTreeSet::from_iter(keys)
            );
        });
    }
}
