// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

// TODO: Move this back to BPro library

use regex::Regex;
#[cfg(feature = "serde")]
use serde_with::{As, DisplayFromStr};
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use bitcoin::util::bip32::{DerivationPath, Fingerprint};
use miniscript::descriptor::DescriptorSinglePub;
use miniscript::{Miniscript, MiniscriptKey, ToPublicKey, TranslatePk2};

use super::{
    DeriveLockScript, Error, ScriptConstruction, ScriptSource, SubCategory,
};
use crate::bip32::{
    ComponentsParseError, DerivationComponents, DerivePublicKey,
    UnhardenedIndex,
};
use crate::script::{LockScript, ToLockScript};

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename = "lowercase", untagged)
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
    StrictDecode,
)]
#[non_exhaustive]
pub enum SingleSig {
    /// Single known public key
    #[cfg_attr(feature = "serde", serde(skip))]
    Pubkey(
        // TODO: Update serde serializer once miniscript will have
        // Display/FromStr #[cfg_attr(feature = "serde", serde(with =
        // "As::<DisplayFromStr>"))]
        DescriptorSinglePub,
    ),

    /// Public key range with deterministic derivation that can be derived
    /// from a known extended public key without private key
    #[cfg_attr(feature = "serde", serde(rename = "xpub"))]
    XPubDerivable(
        #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
        DerivationComponents,
    ),
}

impl Display for SingleSig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SingleSig::Pubkey(pk) => {
                if let Some((fp, path)) = &pk.origin {
                    let path = path.to_string().replace("m/", "");
                    write!(f, "[{}]/{}/", fp, path)?;
                }
                Display::fmt(&pk.key, f)
            }
            SingleSig::XPubDerivable(xpub) => Display::fmt(xpub, f),
        }
    }
}

impl SingleSig {
    pub fn count(&self) -> u32 {
        match self {
            SingleSig::Pubkey(_) => 1,
            SingleSig::XPubDerivable(ref components) => components.count(),
        }
    }
}

impl DerivePublicKey for SingleSig {
    fn derive_public_key(
        &self,
        child_index: UnhardenedIndex,
    ) -> bitcoin::PublicKey {
        match self {
            SingleSig::Pubkey(ref pkd) => pkd.key.to_public_key(),
            SingleSig::XPubDerivable(ref dc) => {
                dc.derive_public_key(child_index)
            }
        }
    }
}

impl MiniscriptKey for SingleSig {
    type Hash = Self;

    fn to_pubkeyhash(&self) -> Self::Hash {
        self.clone()
    }
}

impl FromStr for SingleSig {
    type Err = ComponentsParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        static ERR: &'static str =
            "wrong build-in pubkey placeholder regex parsing syntax";

        lazy_static! {
            static ref RE_PUBKEY: Regex = Regex::new(
                r"(?x)^
                (\[
                    (?P<fingerprint>[0-9A-Fa-f]{8})      # Fingerprint
                    (?P<deviation>(/[0-9]{1,10}[h']?)+)  # Derivation path
                \])?
                (?P<pubkey>0[2-3][0-9A-Fa-f]{64}) |      # Compressed pubkey
                (?P<pubkey_long>04[0-9A-Fa-f]{128})      # Non-compressed pubkey
                $",
            )
            .expect(ERR);
        }
        if let Some(caps) = RE_PUBKEY.captures(s) {
            let origin = if let Some((fp, deriv)) =
                caps.name("fingerprint").map(|fp| {
                    (fp.as_str(), caps.name("derivation").expect(ERR).as_str())
                }) {
                let fp = fp
                    .parse::<Fingerprint>()
                    .map_err(|err| ComponentsParseError(err.to_string()))?;
                let deriv = format!("m/{}", deriv)
                    .parse::<DerivationPath>()
                    .map_err(|err| ComponentsParseError(err.to_string()))?;
                Some((fp, deriv))
            } else {
                None
            };
            let key = bitcoin::PublicKey::from_str(
                caps.name("pubkey")
                    .or(caps.name("pubkey_long"))
                    .expect(ERR)
                    .as_str(),
            )
            .map_err(|err| ComponentsParseError(err.to_string()))?;
            Ok(SingleSig::Pubkey(DescriptorSinglePub { origin, key }))
        } else {
            Ok(SingleSig::XPubDerivable(DerivationComponents::from_str(s)?))
        }
    }
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
    StrictDecode,
)]
pub struct MultiSig {
    pub threshold: Option<u8>,

    #[cfg_attr(feature = "serde", serde(with = "As::<Vec<DisplayFromStr>>"))]
    pub pubkeys: Vec<SingleSig>,

    pub reorder: bool,
}

impl Display for MultiSig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "multi({},", self.threshold())?;
        f.write_str(
            &self
                .pubkeys
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        )?;
        f.write_str(")")
    }
}

impl MultiSig {
    pub fn threshold(&self) -> usize {
        self.threshold
            .map(|t| t as usize)
            .unwrap_or(self.pubkeys.len())
    }

    pub fn derive_public_keys(
        &self,
        child_index: UnhardenedIndex,
    ) -> Vec<bitcoin::PublicKey> {
        let mut set = self
            .pubkeys
            .iter()
            .map(|key| key.derive_public_key(child_index))
            .collect::<Vec<_>>();
        if self.reorder {
            set.sort();
        }
        set
    }
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
    StrictDecode,
)]
pub struct MuSigBranched {
    #[cfg_attr(feature = "serde", serde(with = "As::<Vec<DisplayFromStr>>"))]
    pub extra_keys: Vec<SingleSig>,

    pub tapscript: ScriptConstruction,

    pub source: Option<String>,
}

impl Display for MuSigBranched {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{};", self.tapscript)?;
        f.write_str(
            &self
                .extra_keys
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        )
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
    StrictDecode,
)]
#[display(inner)]
#[non_exhaustive]
pub enum Template {
    SingleSig(
        #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
        SingleSig,
    ),

    MultiSig(MultiSig),

    Scripted(ScriptSource),

    #[cfg_attr(feature = "serde", serde(rename = "musig"))]
    MuSigBranched(MuSigBranched),
}

// TODO: Provide full implementation
impl FromStr for Template {
    type Err = ComponentsParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Template::SingleSig(SingleSig::from_str(s)?))
    }
}

impl Template {
    pub fn is_singlesig(&self) -> bool {
        match self {
            Template::SingleSig(_) => true,
            _ => false,
        }
    }

    pub fn try_derive_public_key(
        &self,
        child_index: UnhardenedIndex,
    ) -> Option<bitcoin::PublicKey> {
        match self {
            Template::SingleSig(key) => {
                Some(key.derive_public_key(child_index))
            }
            _ => None,
        }
    }
}

impl DeriveLockScript for SingleSig {
    fn derive_lock_script(
        &self,
        child_index: UnhardenedIndex,
        descr_category: SubCategory,
    ) -> Result<LockScript, Error> {
        Ok(self
            .derive_public_key(child_index)
            .to_lock_script(descr_category))
    }
}

impl DeriveLockScript for MultiSig {
    fn derive_lock_script(
        &self,
        child_index: UnhardenedIndex,
        descr_category: SubCategory,
    ) -> Result<LockScript, Error> {
        match descr_category {
            SubCategory::SegWit | SubCategory::Nested => {
                let ms = Miniscript::<_, miniscript::Segwitv0>::from_ast(
                    miniscript::Terminal::Multi(
                        self.threshold(),
                        self.pubkeys.clone(),
                    ),
                )
                .expect("miniscript is unable to produce mutisig");
                let ms = ms.translate_pk2(|pk| {
                    if pk.is_uncompressed() {
                        return Err(Error::UncompressedKeyInSegWitContext);
                    }
                    Ok(pk.derive_public_key(child_index))
                })?;
                Ok(ms.encode().into())
            }
            SubCategory::Taproot => unimplemented!(),
            _ => {
                let ms = Miniscript::<_, miniscript::Legacy>::from_ast(
                    miniscript::Terminal::Multi(
                        self.threshold(),
                        self.pubkeys.clone(),
                    ),
                )
                .expect("miniscript is unable to produce mutisig");
                let ms = ms.translate_pk2_infallible(|pk| {
                    pk.derive_public_key(child_index)
                });
                Ok(ms.encode().into())
            }
        }
    }
}

impl DeriveLockScript for MuSigBranched {
    fn derive_lock_script(
        &self,
        _child_index: UnhardenedIndex,
        _descr_category: SubCategory,
    ) -> Result<LockScript, Error> {
        // TODO: Implement after Taproot release
        unimplemented!()
    }
}

impl DeriveLockScript for Template {
    fn derive_lock_script(
        &self,
        child_index: UnhardenedIndex,
        descr_category: SubCategory,
    ) -> Result<LockScript, Error> {
        match self {
            Template::SingleSig(key) => {
                key.derive_lock_script(child_index, descr_category)
            }
            Template::MultiSig(multisig) => {
                multisig.derive_lock_script(child_index, descr_category)
            }
            Template::Scripted(scripted) => {
                scripted.derive_lock_script(child_index, descr_category)
            }
            Template::MuSigBranched(musig) => {
                musig.derive_lock_script(child_index, descr_category)
            }
        }
    }
}
