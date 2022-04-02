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

use crate::{InputMap, OutputMap};
use bitcoin::{TxIn, TxOut};

/// Trait for PSBT "terminals": inputs and outputs, combining both transaction
/// input/output and associated PSBT map into a single structure, like done
/// in PSBTv2.
pub trait Terminal<'psbt, TxTerm>
where
    Self: 'psbt,
{
    type MapType;
    fn with(map: &'psbt mut Self::MapType, tx: &'psbt mut TxTerm, index: usize) -> Self;
    fn index(&self) -> usize;
    fn split(self) -> (&'psbt mut Self::MapType, &'psbt mut TxTerm, usize);
    fn as_map(&self) -> &Self::MapType;
    fn as_tx(&self) -> &TxTerm;
    fn as_map_mut(&mut self) -> &mut Self::MapType;
    fn as_tx_mut(&mut self) -> &mut TxTerm;
}

#[derive(Clone, PartialEq, Default, Debug)]
pub struct Input<'psbt> {
    map: &'psbt mut InputMap,
    txin: &'psbt mut TxIn,
    index: usize,
}

#[derive(Clone, PartialEq, Default, Debug)]
pub struct Output<'psbt> {
    map: &'psbt mut OutputMap,
    txout: &'psbt mut TxOut,
    index: usize,
}

impl<'psbt> Terminal<'psbt, TxIn> for Input<'psbt>
where
    Self: 'psbt,
{
    type MapType = InputMap;

    fn with(map: &'psbt mut InputMap, tx: &'psbt mut TxIn, index: usize) -> Self {
        Self {
            map,
            txin: tx,
            index,
        }
    }

    fn index(&self) -> usize {
        self.index
    }

    fn split(self) -> (&'psbt mut InputMap, &'psbt mut TxIn, usize) {
        (self.map, self.txin, self.index)
    }

    fn as_map(&self) -> &InputMap {
        self.map
    }

    fn as_tx(&self) -> &TxIn {
        self.txin
    }

    fn as_map_mut(&mut self) -> &mut InputMap {
        &mut self.map
    }

    fn as_tx_mut(&mut self) -> &mut TxIn {
        &mut self.txin
    }
}

impl<'psbt> Terminal<'psbt, TxOut> for Output<'psbt>
where
    Self: 'psbt,
{
    type MapType = OutputMap;

    fn with(map: &'psbt mut OutputMap, tx: &'psbt mut TxOut, index: usize) -> Self {
        Self {
            map,
            txout: tx,
            index,
        }
    }

    fn index(&self) -> usize {
        self.index
    }

    fn split(self) -> (&'psbt mut OutputMap, &'psbt mut TxOut, usize) {
        (self.map, self.txout, self.index)
    }

    fn as_map(&self) -> &OutputMap {
        self.map
    }

    fn as_tx(&self) -> &TxOut {
        self.txout
    }

    fn as_map_mut(&mut self) -> &mut OutputMap {
        &mut self.map
    }

    fn as_tx_mut(&mut self) -> &mut TxOut {
        &mut self.txout
    }
}
