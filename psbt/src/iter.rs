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

use crate::{Input, Output, Psbt, Terminal};

pub struct InputIter<'psbt> {
    psbt: &'psbt mut Psbt,
    next_index: usize,
}

pub struct OutputIter<'psbt> {
    psbt: &'psbt mut Psbt,
    next_index: usize,
}

impl<'psbt> From<&'psbt mut Psbt> for InputIter<'psbt>
where
    Self: 'psbt,
{
    fn from(psbt: &'psbt mut Psbt) -> Self {
        InputIter {
            psbt,
            next_index: 0,
        }
    }
}

impl<'psbt> From<&'psbt mut Psbt> for OutputIter<'psbt>
where
    Self: 'psbt,
{
    fn from(psbt: &'psbt mut Psbt) -> Self {
        OutputIter {
            psbt,
            next_index: 0,
        }
    }
}

impl<'psbt> Iterator for InputIter<'psbt>
where
    Self: 'psbt,
{
    type Item = Input<'psbt>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_index >= self.psbt.inputs.len() {
            return None;
        }
        let input = Input::with(
            &mut self.psbt.inputs[self.next_index],
            &mut self.psbt.unsigned_tx.input[self.next_index],
            self.next_index,
        );
        self.next_index += 1;
        return Some(input);
    }
}

impl<'psbt> Iterator for OutputIter<'psbt>
where
    Self: 'psbt,
{
    type Item = Output<'psbt>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_index >= self.psbt.outputs.len() {
            return None;
        }
        let output = Output::with(
            &mut self.psbt.outputs[self.next_index],
            &mut self.psbt.unsigned_tx.output[self.next_index],
            self.next_index,
        );
        self.next_index += 1;
        return Some(output);
    }
}
