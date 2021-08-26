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

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use amplify::Wrapper;
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Builder;
use bitcoin::secp256k1::{Secp256k1, Verification};
use bitcoin::Script;
use bitcoin_hd::{DerivePublicKey, UnhardenedIndex};
use miniscript::{policy, Miniscript, MiniscriptKey};
#[cfg(feature = "serde")]
use serde_with::{hex::Hex, As, DisplayFromStr};
use strict_encoding::{self, StrictDecode, StrictEncode};

use super::SingleSig;

/// Allows creating templates for native bitcoin scripts with embedded
/// key generator templates. May be useful for creating descriptors in
/// situations where target script can't be deterministically represented by
/// miniscript, for instance for Lightning network-specific transaction outputs
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename = "lowercase")
)]
#[derive(
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Debug,
    Hash,
    Display,
    StrictEncode,
    StrictDecode
)]
pub enum OpcodeTemplate<Pk>
where
    Pk: MiniscriptKey + StrictEncode + StrictDecode + FromStr,
    <Pk as FromStr>::Err: Display,
{
    /// Normal script command (OP_CODE)
    #[display("opcode({0})")]
    OpCode(u8),

    /// Binary data (follows push commands)
    #[display("data({0:#x?})")]
    Data(#[cfg_attr(feature = "serde", serde(with = "As::<Hex>"))] Box<[u8]>),

    /// Key template
    #[display("key({0})")]
    Key(
        #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))] Pk,
    ),
}

impl<Pk> OpcodeTemplate<Pk>
where
    Pk: MiniscriptKey + DerivePublicKey + StrictEncode + StrictDecode + FromStr,
    <Pk as FromStr>::Err: Display,
{
    fn translate_pk<C: Verification>(
        &self,
        ctx: &Secp256k1<C>,
        child_index: UnhardenedIndex,
    ) -> OpcodeTemplate<bitcoin::PublicKey> {
        match self {
            OpcodeTemplate::OpCode(code) => OpcodeTemplate::OpCode(*code),
            OpcodeTemplate::Data(data) => OpcodeTemplate::Data(data.clone()),
            OpcodeTemplate::Key(key) => {
                OpcodeTemplate::Key(key.derive_public_key(ctx, child_index))
            }
        }
    }
}

/// Allows creating templates for native bitcoin scripts with embedded
/// key generator templates. May be useful for creating descriptors in
/// situations where target script can't be deterministically represented by
/// miniscript, for instance for Lightning network-specific transaction outputs
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(
    Wrapper,
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    From,
    StrictEncode,
    StrictDecode
)]
#[wrap(Index, IndexMut, IndexFull, IndexFrom, IndexTo, IndexInclusive)]
pub struct ScriptTemplate<Pk>(Vec<OpcodeTemplate<Pk>>)
where
    Pk: MiniscriptKey + StrictEncode + StrictDecode + FromStr,
    <Pk as FromStr>::Err: Display;

impl<Pk> Display for ScriptTemplate<Pk>
where
    Pk: MiniscriptKey + StrictEncode + StrictDecode + FromStr,
    <Pk as FromStr>::Err: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for instruction in &self.0 {
            Display::fmt(instruction, f)?;
        }
        Ok(())
    }
}

impl<Pk> ScriptTemplate<Pk>
where
    Pk: MiniscriptKey + DerivePublicKey + StrictEncode + StrictDecode + FromStr,
    <Pk as FromStr>::Err: Display,
{
    pub fn translate_pk<C: Verification>(
        &self,
        ctx: &Secp256k1<C>,
        child_index: UnhardenedIndex,
    ) -> ScriptTemplate<bitcoin::PublicKey> {
        self.0
            .iter()
            .map(|op| op.translate_pk(ctx, child_index))
            .collect::<Vec<_>>()
            .into()
    }
}

impl From<ScriptTemplate<bitcoin::PublicKey>> for Script {
    fn from(template: ScriptTemplate<bitcoin::PublicKey>) -> Self {
        let mut builder = Builder::new();
        for op in template.into_inner() {
            builder = match op {
                OpcodeTemplate::OpCode(code) => {
                    builder.push_opcode(opcodes::All::from(code))
                }
                OpcodeTemplate::Data(data) => builder.push_slice(&data),
                OpcodeTemplate::Key(key) => builder.push_key(&key),
            };
        }
        builder.into_script()
    }
}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename = "lowercase")
)]
#[derive(
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode
)]
#[non_exhaustive]
#[display(inner)]
#[allow(clippy::large_enum_variant)]
pub enum ScriptConstruction {
    #[cfg_attr(feature = "serde", serde(rename = "script"))]
    ScriptTemplate(ScriptTemplate<SingleSig>),

    Miniscript(
        #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
        Miniscript<SingleSig, miniscript::Segwitv0>,
    ),

    #[cfg_attr(feature = "serde", serde(rename = "policy"))]
    MiniscriptPolicy(
        #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
        policy::Concrete<SingleSig>,
    ),
}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    StrictEncode,
    StrictDecode
)]
pub struct ScriptSource {
    pub script: ScriptConstruction,

    pub source: Option<String>,

    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<Option<DisplayFromStr>>")
    )]
    pub tweak_target: Option<SingleSig>,
}

impl Display for ScriptSource {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(ref source) = self.source {
            f.write_str(source)
        } else {
            Display::fmt(&self.script, f)
        }
    }
}

/// Representation formats for bitcoin script data
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[cfg_attr(feature = "clap", Clap)]
#[cfg_attr(feature = "strict_encoding", derive(StrictEncode, StrictDecode))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename = "lowercase")
)]
#[non_exhaustive]
pub enum ScriptSourceFormat {
    /// Binary script source encoded as hexadecimal string
    #[display("hex")]
    Hex,

    /// Binary script source encoded as Base64 string
    #[display("base64")]
    Base64,

    /// Miniscript string or descriptor
    #[display("miniscript")]
    Miniscript,

    /// Miniscript string or descriptor
    #[display("policy")]
    Policy,

    /// String with assembler opcodes
    #[display("asm")]
    Asm,
}
