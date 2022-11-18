//! Experiments on new descriptor type system

#![allow(unused)]

use std::collections::HashMap;
use std::hash::Hash;

use amplify::Slice32;
use bitcoin::util::bip32::ChainCode;
use bitcoin::XOnlyPublicKey;
use bitcoin_hd::{DerivationSubpath, TerminalStep, UnhardenedIndex};
use bitcoin_scripts::address::AddressPayload;
use bitcoin_scripts::{LeafScript, TapNodeHash};
use miniscript_crate::{Legacy, Miniscript, MiniscriptKey, Segwitv0, Tap};

pub trait ScriptData: MiniscriptKey {
    type Key;
    type CompKey;
    type XonlyKey;
    type Definite;
}

pub trait Descriptor {
    type Translated;
    fn translate(&self) -> Self::Translated;
}

pub struct AccDescr<D: ScriptData, K: ScriptData, const TERM_LEN: usize> {
    keys: HashMap<D, K>,
    descr: OutputDescr<D>,
    terminal: Option<DerivationSubpath<TerminalStep>>,
    tapret: Vec<TapretInfo<TERM_LEN>>,
}

pub struct TapretInfo<const TERM_LEN: usize> {
    pub terminal: [UnhardenedIndex; TERM_LEN],
    pub nonce: u8,
    pub tweak: Slice32,
}

impl<D: ScriptData, K: ScriptData, const TERM_LEN: usize> Descriptor for AccDescr<D, K, TERM_LEN> {
    type Translated = K::Definite;
    fn translate(&self) -> K::Definite { todo!() }
}

// Temporary type holder
pub type AccId = Slice32;
// Temporary type holder
pub type AccStateId = Slice32;

impl<D: ScriptData, K: ScriptData, const TERM_LEN: usize> AccDescr<D, K, TERM_LEN> {
    pub fn id() -> AccId { todo!("commit to permanent parts") }
    pub fn state_id() -> AccStateId { todo!("commit to variable parts") }
}

pub enum OutputDescr<D: ScriptData> {
    Sh(ScriptDescr<D>),
    Wsh(WScriptDescr<D>),
    Pk(D),
    Pkh(D),
    Wpkh(D),

    Combo(ComboDescr<D>),
    Multi(MultiDescr<D, false>),
    Sortedmulti(MultiDescr<D, true>),

    Tr(TapKeyDescr<D>, TapNodeDescr<D>),

    Raw(ScriptDescr<D>),
    RawTr(XOnlyPublicKey),

    Addr(AddressPayload),
}

pub enum ScriptDescr<D: ScriptData> {
    Bitcoin(BitcoinScript<D>),
    Miniscript(Miniscript<D, Legacy>),
}

pub enum WScriptDescr<D: ScriptData> {
    Bitcoin(BitcoinScript<D>),
    Miniscript(Miniscript<D, Segwitv0>),
}

pub struct ComboDescr<D: ScriptData>(Vec<D> /* at least 1 element, no repeated elements */);

pub struct MultiDescr<D: ScriptData, const SORTED: bool> {
    threshold: u8,
    keys: Vec<D>, // at least 1 element, no repeated elements, ensure # >= threshold
}

pub enum TapKeyDescr<D: ScriptData> {
    Unspend(ChainCode, DerivationSubpath<TerminalStep>),
    Key(D),
    MuSig(Vec<D>),
}

pub enum TapNodeDescr<D: ScriptData> {
    TapScript(TapScript<D>),
    TapMiniscript(Miniscript<D, Tap>),
    RawLeaf(LeafScript),
    RawNode(TapNodeHash),
    Branch(Box<TapNodeDescr<D>>, Box<TapNodeDescr<D>>),
}

pub struct BitcoinScript<D: ScriptData> {
    instructions: Vec<LegacyInstr<D>>,
}

pub struct TapScript<D: ScriptData> {
    instructions: Vec<TapInstr<D>>,
}

pub enum LegacyInstr<D: ScriptData> {
    Data(D), // enumerate opcodes
}

pub enum TapInstr<D: ScriptData> {
    Data(D), // enumerate opcodes
}
