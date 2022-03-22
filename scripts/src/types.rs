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

use std::convert::TryFrom;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Read, Write};

use amplify::hex::ToHex;
use amplify::{hex, Wrapper};
use bitcoin::blockdata::script::*;
use bitcoin::blockdata::witness::Witness;
use bitcoin::blockdata::{opcodes, script};
use bitcoin::schnorr::TweakedPublicKey;
use bitcoin::util::address::WitnessVersion;
use bitcoin::util::taproot::{ControlBlock, LeafVersion, TaprootError, TAPROOT_ANNEX_PREFIX};
use bitcoin::{
    consensus, Address, Network, PubkeyHash, SchnorrSig, SchnorrSigError, ScriptHash, WPubkeyHash,
    WScriptHash,
};

/// Script whose knowledge and satisfaction is required for spending some
/// specific transaction output. This is the deepest nested version of Bitcoin
/// script containing no hashes of other scripts, including P2SH `redeemScript`
/// hashes or `witnessProgram` (hash or witness script), or public key hashes.
/// It is also used for representing specific spending branch of the taproot
/// script tree.
///
/// [`LockScript`] defines no specific script semantics for opcodes, which is
/// imposed by other contexts on top of it, like [`WitnessScript`],
/// [`LeafScript`] or [`TapScript`].
#[derive(
    Wrapper, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug, Display, From
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[display("{0}", alt = "{0:x}")]
#[wrapper(LowerHex, UpperHex)]
pub struct LockScript(Script);

impl strict_encoding::Strategy for LockScript {
    type Strategy = strict_encoding::strategies::Wrapped;
}

/// A representation of `scriptPubkey` data used during SegWit signing procedure
#[derive(
    Wrapper, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug, Display, From
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[display("{0}", alt = "{0:x}")]
#[wrapper(LowerHex, UpperHex)]
pub struct ScriptCode(Script);

/// A content of `scriptPubkey` from a transaction output
#[derive(
    Wrapper, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug, Display, From
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[display("{0}", alt = "{0:x}")]
#[wrapper(LowerHex, UpperHex)]
pub struct PubkeyScript(Script);

impl strict_encoding::Strategy for PubkeyScript {
    type Strategy = strict_encoding::strategies::Wrapped;
}

impl PubkeyScript {
    /// Generates an address matching the script and given network, if possible.
    ///
    /// Address generation is not possible for bare scripts and P2PK; in this
    /// case the function returns `None`.
    pub fn address(&self, network: Network) -> Option<Address> {
        Address::from_script(self.as_inner(), network)
    }

    /// Returns witness version of the `scriptPubkey`, if any
    // TODO: Replace with Script::witness_version once # in rust-bitcoin gets merged
    pub fn witness_version(&self) -> Option<WitnessVersion> {
        self.0
            .as_ref()
            .get(0)
            .and_then(|opcode| WitnessVersion::from_opcode(opcodes::All::from(*opcode)).ok())
    }
}

impl From<PubkeyHash> for PubkeyScript {
    fn from(pkh: PubkeyHash) -> Self { Script::new_p2pkh(&pkh).into() }
}

impl From<WPubkeyHash> for PubkeyScript {
    fn from(wpkh: WPubkeyHash) -> Self { Script::new_v0_p2wpkh(&wpkh).into() }
}

/// A content of `scriptSig` from a transaction input
#[derive(
    Wrapper, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug, Display, From
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[display("{0}", alt = "{0:x}")]
#[wrapper(LowerHex, UpperHex)]
pub struct SigScript(Script);

impl strict_encoding::Strategy for SigScript {
    type Strategy = strict_encoding::strategies::Wrapped;
}

/// Errors for [`TaprootWitness`] construction from [`Witness`] and byte
/// representations
#[derive(Debug, Display, From)]
#[display(doc_comments)]
pub enum TaprootWitnessError {
    /// witness stack has zero elements
    EmptyWitnessStack,

    /// BIP-341 signature encoding error in witness data
    #[from]
    Bip341SigError(SchnorrSigError),

    #[display(inner)]
    #[from]
    TaprootError(TaprootError),

    /// script encoding error
    ScriptError(bitcoin::consensus::encode::Error),
}

impl std::error::Error for TaprootWitnessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TaprootWitnessError::EmptyWitnessStack => None,
            TaprootWitnessError::Bip341SigError(err) => Some(err),
            TaprootWitnessError::TaprootError(_) => None,
            TaprootWitnessError::ScriptError(err) => Some(err),
        }
    }
}

/// Parsed witness stack for Taproot inputs
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub enum TaprootWitness {
    /// Public key path spending
    PubkeySpending {
        /// BIP-341 signature
        sig: SchnorrSig,
        /// Optional annex data (annex prefix is removed)
        annex: Option<Box<[u8]>>,
    },

    /// Script path spending
    ScriptSpending {
        /// Taproot control block
        control_block: ControlBlock,
        /// Optional annex data (annex prefix is removed)
        annex: Option<Box<[u8]>>,
        /// Leaf script for the spending
        script: LeafScript,
        /// The remaining part of the witness stack
        script_input: Vec<Box<[u8]>>,
    },
}

impl TryFrom<Witness> for TaprootWitness {
    type Error = TaprootWitnessError;

    fn try_from(witness: Witness) -> Result<Self, Self::Error> {
        if witness.is_empty() {
            return Err(TaprootWitnessError::EmptyWitnessStack);
        }

        let mut len = witness.len();
        let annex = if len > 1 {
            witness
                .last()
                .filter(|annex| annex[0] == TAPROOT_ANNEX_PREFIX)
                .map(Box::from)
        } else {
            None
        };
        if annex.is_some() {
            len -= 1;
        }

        Ok(if len == 1 {
            TaprootWitness::PubkeySpending {
                sig: SchnorrSig::from_slice(
                    witness
                        .last()
                        .expect("witness must have at least 1 element"),
                )?,
                annex,
            }
        } else {
            let (control_block, script) = if annex.is_some() {
                (
                    witness
                        .second_to_last()
                        .expect("witness must have at least 3 elements"),
                    witness
                        .iter()
                        .nth(len - 2)
                        .expect("witness must have at least 3 elements"),
                )
            } else {
                (
                    witness
                        .last()
                        .expect("witness must have at least 2 elements"),
                    witness
                        .second_to_last()
                        .expect("witness must have at least 2 elements"),
                )
            };
            let control_block = ControlBlock::from_slice(control_block)?;
            let script = bitcoin::consensus::deserialize(script)
                .map_err(TaprootWitnessError::ScriptError)?;
            let script = LeafScript {
                version: control_block.leaf_version,
                script: LockScript::from_inner(script),
            };
            TaprootWitness::ScriptSpending {
                control_block,
                annex,
                script,
                script_input: witness.iter().take(len - 2).map(Box::from).collect(),
            }
        })
    }
}

impl From<TaprootWitness> for Witness {
    #[inline]
    fn from(tw: TaprootWitness) -> Self { Witness::from(&tw) }
}

impl From<&TaprootWitness> for Witness {
    fn from(tw: &TaprootWitness) -> Self {
        let mut witness = Witness::default();
        match tw {
            TaprootWitness::PubkeySpending { sig, annex } => {
                witness.push(&sig.to_vec());
                if let Some(annex) = annex {
                    witness.push(annex);
                }
            }
            TaprootWitness::ScriptSpending {
                control_block,
                annex,
                script,
                script_input,
            } => {
                for item in script_input {
                    witness.push(item);
                }
                witness.push(&bitcoin::consensus::serialize(&script.script.0));
                witness.push(&control_block.serialize());
                if let Some(annex) = annex {
                    witness.push(annex);
                }
            }
        }
        witness
    }
}

impl strict_encoding::Strategy for TaprootWitness {
    type Strategy = strict_encoding::strategies::BitcoinConsensus;
}

impl bitcoin::consensus::Encodable for TaprootWitness {
    fn consensus_encode<W: Write>(&self, writer: W) -> Result<usize, io::Error> {
        Witness::from(self).consensus_encode(writer)
    }
}

impl bitcoin::consensus::Decodable for TaprootWitness {
    fn consensus_decode<D: Read>(d: D) -> Result<Self, bitcoin::consensus::encode::Error> {
        TaprootWitness::try_from(Witness::consensus_decode(d)?).map_err(|_| {
            bitcoin::consensus::encode::Error::ParseFailed("witness does not conform to taproot")
        })
    }
}

/// Redeem script as part of the `witness` or `scriptSig` structure; it is
/// hashed for P2(W)SH output.
#[derive(
    Wrapper, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug, Display, From
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[display("{0}", alt = "{0:x}")]
#[wrapper(LowerHex, UpperHex)]
pub struct RedeemScript(Script);

impl strict_encoding::Strategy for RedeemScript {
    type Strategy = strict_encoding::strategies::Wrapped;
}

impl RedeemScript {
    /// Computes script commitment hash which participates in [`PubkeyScript`]
    #[inline]
    pub fn script_hash(&self) -> ScriptHash { self.as_inner().script_hash() }

    /// Generates [`PubkeyScript`] matching given `redeemScript`
    #[inline]
    pub fn to_p2sh(&self) -> PubkeyScript { Script::new_p2sh(&self.script_hash()).into() }
}

impl From<RedeemScript> for SigScript {
    #[inline]
    fn from(redeem_script: RedeemScript) -> Self {
        script::Builder::new()
            .push_slice(redeem_script.as_bytes())
            .into_script()
            .into()
    }
}

/// A content of the script from `witness` structure; en equivalent of
/// `redeemScript` for witness-based transaction inputs. However, unlike
/// [`RedeemScript`], [`WitnessScript`] produce SHA256-based hashes of
/// [`WScriptHash`] type.
///
/// Witness script can be nested within the redeem script in legacy
/// P2WSH-in-P2SH schemes; for this purpose use [`RedeemScript::from`] method.
#[derive(
    Wrapper, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug, Display, From
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[display("{0}", alt = "{0:x}")]
#[wrapper(LowerHex, UpperHex)]
pub struct WitnessScript(Script);

impl strict_encoding::Strategy for WitnessScript {
    type Strategy = strict_encoding::strategies::Wrapped;
}

impl WitnessScript {
    /// Computes script commitment which participates in [`Witness`] or
    /// [`RedeemScript`].
    #[inline]
    pub fn script_hash(&self) -> WScriptHash { self.as_inner().wscript_hash() }

    /// Generates [`PubkeyScript`] matching given `witnessScript` for native
    /// SegWit outputs.
    #[inline]
    pub fn to_p2wsh(&self) -> PubkeyScript { Script::new_v0_p2wsh(&self.script_hash()).into() }

    /// Generates [`PubkeyScript`] matching given `witnessScript` for legacy
    /// P2WSH-in-P2SH outputs.
    #[inline]
    pub fn to_p2sh_wsh(&self) -> PubkeyScript { RedeemScript::from(self.clone()).to_p2sh() }
}

impl From<WitnessScript> for RedeemScript {
    fn from(witness_script: WitnessScript) -> Self {
        RedeemScript(Script::new_v0_p2wsh(&witness_script.script_hash()))
    }
}

impl From<LockScript> for WitnessScript {
    fn from(lock_script: LockScript) -> Self { WitnessScript(lock_script.to_inner()) }
}

impl From<LockScript> for RedeemScript {
    fn from(lock_script: LockScript) -> Self { RedeemScript(lock_script.to_inner()) }
}

impl From<WitnessScript> for LockScript {
    fn from(witness_script: WitnessScript) -> Self { LockScript(witness_script.to_inner()) }
}

impl From<RedeemScript> for LockScript {
    fn from(redeem_script: RedeemScript) -> Self { LockScript(redeem_script.to_inner()) }
}

/// Any valid branch of taproot script spending
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display("{version} {script}", alt = "{version:#} {script:x}")]
pub struct LeafScript {
    /// Leaf version of the script
    pub version: LeafVersion,

    /// Script data
    pub script: LockScript,
}

impl strict_encoding::StrictEncode for LeafScript {
    fn strict_encode<E: Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
        self.version.into_consensus().strict_encode(&mut e)?;
        self.script.as_inner().to_bytes().strict_encode(&mut e)
    }
}

impl strict_encoding::StrictDecode for LeafScript {
    fn strict_decode<D: Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        let version = u8::strict_decode(&mut d)?;
        let version = LeafVersion::from_consensus(version)
            .map_err(|_| bitcoin::consensus::encode::Error::ParseFailed("invalid leaf version"))?;
        let script = LockScript::from_inner(Script::from(Vec::<u8>::strict_decode(d)?));
        Ok(LeafScript { version, script })
    }
}

impl LeafScript {
    /// Constructs tapscript
    #[inline]
    pub fn tapscript(script: Script) -> LeafScript {
        LeafScript {
            version: LeafVersion::TapScript,
            script: script.into(),
        }
    }
}

/// Script at specific taproot script spend path for `0xC0` tapleaf version,
/// which semantics are defined in BIP-342.
#[derive(
    Wrapper, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug, Display, From
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[display("{0}", alt = "{0:x}")]
#[wrapper(LowerHex, UpperHex)]
pub struct TapScript(Script);

impl strict_encoding::Strategy for TapScript {
    type Strategy = strict_encoding::strategies::Wrapped;
}

impl From<LockScript> for TapScript {
    fn from(lock_script: LockScript) -> Self { TapScript(lock_script.to_inner()) }
}

impl From<TapScript> for LeafScript {
    fn from(tap_script: TapScript) -> Self {
        LeafScript {
            version: LeafVersion::TapScript,
            script: LockScript::from_inner(tap_script.into_inner()),
        }
    }
}

/// Witness program: a part of post-segwit `scriptPubkey`; a data pushed to the
/// stack following witness version
#[derive(
    Wrapper, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug, From
)]
pub struct WitnessProgram(Box<[u8]>);

impl strict_encoding::Strategy for WitnessProgram {
    type Strategy = strict_encoding::strategies::Wrapped;
}

impl Display for WitnessProgram {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { writeln!(f, "{}", self.0.to_hex()) }
}

impl From<WPubkeyHash> for WitnessProgram {
    #[inline]
    fn from(wpkh: WPubkeyHash) -> Self { WitnessProgram(Box::from(&wpkh[..])) }
}

impl From<WScriptHash> for WitnessProgram {
    #[inline]
    fn from(wsh: WScriptHash) -> Self { WitnessProgram(Box::from(&wsh[..])) }
}

impl From<TweakedPublicKey> for WitnessProgram {
    #[inline]
    fn from(tpk: TweakedPublicKey) -> Self { WitnessProgram(Box::from(&tpk.serialize()[..])) }
}

/// Scripting data for both transaction output and spending transaction input
/// parts that can be generated from some complete bitcoin Script
/// ([`LockScript`]) or public key using particular [`crate::ConvertInfo`]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Default)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct ScriptSet {
    /// Transaction output `scriptPubkey`
    pub pubkey_script: PubkeyScript,
    /// Transaction input `sigScript`, without satisfaction data (signatures,
    /// public keys etc)
    pub sig_script: SigScript,
    /// Transaction input `witness`, without satisfaction data (signatures,
    /// public keys etc)
    pub witness: Option<Witness>,
}

impl Display for ScriptSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} ", self.sig_script,)?;
        hex::format_hex(
            &self
                .witness
                .as_ref()
                .map(consensus::serialize)
                .unwrap_or_default(),
            f,
        )?;
        write!(f, " <- {}", self.pubkey_script)
    }
}

impl ScriptSet {
    /// Detects whether the structure contains witness data
    #[inline]
    pub fn has_witness(&self) -> bool { self.witness != None }

    /// Detects whether the structure is either P2SH-P2WPKH or P2SH-P2WSH
    pub fn is_witness_sh(&self) -> bool {
        return !self.sig_script.as_inner().is_empty() && self.has_witness();
    }

    /// Tries to convert witness-based script structure into pre-SegWit – and
    /// vice verse. Returns `true` if the conversion is possible and was
    /// successful, `false` if the conversion is impossible; in the later case
    /// the `self` is not changed. The conversion is impossible in the following
    /// cases:
    /// * for P2SH-P2WPKH or P2SH-P2WPSH variants (can be detected with
    ///   [ScriptSet::is_witness_sh] function)
    /// * for scripts that are internally inconsistent
    pub fn transmutate(&mut self, use_witness: bool) -> bool {
        // We can't transmutate P2SH-contained P2WSH/P2WPKH
        if self.is_witness_sh() {
            return false;
        }
        if self.has_witness() != use_witness {
            if use_witness {
                let witness = self
                    .sig_script
                    .as_inner()
                    .instructions_minimal()
                    .filter_map(|instr| {
                        if let Ok(Instruction::PushBytes(bytes)) = instr {
                            Some(bytes.to_vec())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<Vec<u8>>>();
                self.witness = Some(Witness::from_vec(witness));
                self.sig_script = SigScript::default();
                true
            } else if let Some(ref witness_script) = self.witness {
                self.sig_script = witness_script
                    .iter()
                    .fold(Builder::new(), |builder, bytes| builder.push_slice(bytes))
                    .into_script()
                    .into();
                self.witness = None;
                true
            } else {
                false
            }
        } else {
            false
        }
    }
}
