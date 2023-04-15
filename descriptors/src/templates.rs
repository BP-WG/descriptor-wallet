// Wallet-level libraries for bitcoin protocol by LNP/BP Association
//
// Written in 2020-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// This software is distributed without any warranty.
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
use bitcoin::ScriptBuf;
use bitcoin_hd::account::DerivePublicKey;
use bitcoin_hd::{DerivePatternError, UnhardenedIndex};
use miniscript::MiniscriptKey;
#[cfg(feature = "serde")]
use serde_with::{hex::Hex, As, DisplayFromStr};
use strict_encoding::{self, StrictDecode, StrictEncode};

/// Allows creating templates for native bitcoin scripts with embedded
/// key generator templates. May be useful for creating descriptors in
/// situations where target script can't be deterministically represented by
/// miniscript, for instance for Lightning network-specific transaction outputs
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename = "lowercase")
)]
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Display)]
#[derive(StrictEncode, StrictDecode)]
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
    Key(#[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))] Pk),
}

impl<Pk> OpcodeTemplate<Pk>
where
    Pk: MiniscriptKey + DerivePublicKey + StrictEncode + StrictDecode + FromStr,
    <Pk as FromStr>::Err: Display,
{
    fn translate_pk<C: Verification>(
        &self,
        ctx: &Secp256k1<C>,
        pat: impl IntoIterator<Item = impl Into<UnhardenedIndex>>,
    ) -> Result<OpcodeTemplate<bitcoin::PublicKey>, DerivePatternError> {
        Ok(match self {
            OpcodeTemplate::OpCode(code) => OpcodeTemplate::OpCode(*code),
            OpcodeTemplate::Data(data) => OpcodeTemplate::Data(data.clone()),
            OpcodeTemplate::Key(key) => {
                OpcodeTemplate::Key(bitcoin::PublicKey::new(key.derive_public_key(ctx, pat)?))
            }
        })
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
#[derive(Wrapper, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[derive(StrictEncode, StrictDecode)]
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
        pat: impl AsRef<[UnhardenedIndex]>,
    ) -> Result<ScriptTemplate<bitcoin::PublicKey>, DerivePatternError> {
        let pat = pat.as_ref();
        Ok(self
            .0
            .iter()
            .map(|op| op.translate_pk(ctx, pat))
            .collect::<Result<Vec<_>, _>>()?
            .into())
    }
}

impl From<ScriptTemplate<bitcoin::PublicKey>> for ScriptBuf {
    fn from(template: ScriptTemplate<bitcoin::PublicKey>) -> Self {
        let mut builder = Builder::new();
        for op in template.into_inner() {
            builder = match op {
                OpcodeTemplate::OpCode(code) => builder.push_opcode(opcodes::All::from(code)),
                OpcodeTemplate::Data(data) => builder.push_slice(&data),
                OpcodeTemplate::Key(key) => builder.push_key(&key),
            };
        }
        builder.into_script()
    }
}
