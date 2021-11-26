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

// TODO: This mod contains accessory methods which should be moved to
//       rust-bitcoin `Derivation Path`

use std::convert::TryFrom;

use bitcoin::util::bip32::{ChildNumber, DerivationPath};

use crate::{AccountStep, SegmentIndexes, TerminalStep};

/// Extension trait allowing to add more methods to [`DerivationPath`] type
pub trait DerivationPathMaster {
    /// Returns derivation path for a master key (i.e. empty derivation path)
    fn master() -> Self;

    /// Returns whether derivation path represents master key (i.e. it's length
    /// is empty). True for `m` path.
    fn is_master(&self) -> bool;
}

impl DerivationPathMaster for DerivationPath {
    fn master() -> DerivationPath { vec![].into() }
    fn is_master(&self) -> bool { self.into_iter().len() == 0 }
}

/// Extension trait allowing splitting derivation paths into hardened and
/// unhardened components
pub trait HardenedNormalSplit {
    /// Splits [`DerivationPath`] into hardened and unhardened parts
    fn hardened_normal_split(&self) -> (Vec<AccountStep>, Vec<TerminalStep>);
}

impl HardenedNormalSplit for DerivationPath {
    fn hardened_normal_split(&self) -> (Vec<AccountStep>, Vec<TerminalStep>) {
        let mut terminal_path = vec![];
        let account_path = self
            .into_iter()
            .rev()
            .by_ref()
            .skip_while(|child| {
                if let ChildNumber::Normal { index } = child {
                    terminal_path.push(
                        TerminalStep::from_index(*index)
                            .expect("ChildNumber::Normal contains hardened index"),
                    );
                    true
                } else {
                    false
                }
            })
            .cloned()
            .map(AccountStep::try_from)
            .collect::<Result<Vec<_>, _>>()
            .expect("ChildNumber indexes are broken");
        let account_path = account_path.into_iter().rev().collect();
        let terminal_path = terminal_path.into_iter().rev().collect();
        (account_path, terminal_path)
    }
}
