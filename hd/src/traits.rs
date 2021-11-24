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

use bitcoin::secp256k1::{self, Secp256k1, Verification};
use bitcoin::util::bip32::{ChildNumber, DerivationPath};

use super::UnhardenedIndex;

/// Method-trait that can be implemented by all types able to derive a
/// public key with a given path
pub trait DerivePublicKey {
    fn derive_public_key<C: Verification>(
        &self,
        ctx: &Secp256k1<C>,
        child_index: UnhardenedIndex,
    ) -> secp256k1::PublicKey;
}

/// Extension trait allowing to add more methods to [`DerivationPath`] type
pub trait DerivationPathMaster {
    fn master() -> Self;
    fn is_master(&self) -> bool;
}

impl DerivationPathMaster for DerivationPath {
    /// Returns derivation path for a master key (i.e. empty derivation path)
    fn master() -> DerivationPath { vec![].into() }

    /// Returns whether derivation path represents master key (i.e. it's length
    /// is empty). True for `m` path.
    fn is_master(&self) -> bool { self.into_iter().len() == 0 }
}

pub trait HardenedNormalSplit {
    fn hardened_normal_split(&self) -> (DerivationPath, Vec<u32>);
}

impl HardenedNormalSplit for DerivationPath {
    fn hardened_normal_split(&self) -> (DerivationPath, Vec<u32>) {
        let mut terminal_path = vec![];
        let branch_path = self
            .into_iter()
            .rev()
            .by_ref()
            .skip_while(|child| {
                if let ChildNumber::Normal { index } = child {
                    terminal_path.push(index);
                    true
                } else {
                    false
                }
            })
            .cloned()
            .collect::<DerivationPath>();
        let branch_path = branch_path.into_iter().rev().cloned().collect();
        let terminal_path = terminal_path.into_iter().rev().cloned().collect();
        (branch_path, terminal_path)
    }
}
