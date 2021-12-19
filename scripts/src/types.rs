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
use std::num::ParseIntError;
use std::str::FromStr;

use amplify::hex::ToHex;
use amplify::Wrapper;
use bitcoin::blockdata::script::*;
use bitcoin::blockdata::{opcodes, script};
use bitcoin::{bech32, Address, Network, PubkeyHash, ScriptHash, WPubkeyHash, WScriptHash};

/// Errors processing [`WitnessVersion`]
#[derive(Debug, PartialEq, Eq, Clone, Display, Error)]
#[display(doc_comments)]
pub enum WitnessVersionError {
    /// Script version must be 0 to 16 inclusive.
    InvalidWitnessVersion(u8),
    /// Unable to parse witness version from string.
    UnparsableWitnessVersion(ParseIntError),
    /// Bitcoin script opcode does not match any known witness version, the
    /// script is malformed.
    MalformedWitnessVersion,
}

/// Version of the witness program.
///
/// Helps limit possible versions of the witness according to the specification.
/// If a plain `u8` type was used instead it would mean that the version may be
/// > 16, which would be incorrect.
///
/// First byte of `scriptPubkey` in transaction output for transactions starting
/// with opcodes ranging from 0 to 16 (inclusive).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(u8)]
pub enum WitnessVersion {
    /// Initial version of witness program. Used for P2WPKH and P2WPK outputs
    V0 = 0,
    /// Version of witness program used for Taproot P2TR outputs.
    V1 = 1,
    /// Future (unsupported) version of witness program.
    V2 = 2,
    /// Future (unsupported) version of witness program.
    V3 = 3,
    /// Future (unsupported) version of witness program.
    V4 = 4,
    /// Future (unsupported) version of witness program.
    V5 = 5,
    /// Future (unsupported) version of witness program.
    V6 = 6,
    /// Future (unsupported) version of witness program.
    V7 = 7,
    /// Future (unsupported) version of witness program.
    V8 = 8,
    /// Future (unsupported) version of witness program.
    V9 = 9,
    /// Future (unsupported) version of witness program.
    V10 = 10,
    /// Future (unsupported) version of witness program.
    V11 = 11,
    /// Future (unsupported) version of witness program.
    V12 = 12,
    /// Future (unsupported) version of witness program.
    V13 = 13,
    /// Future (unsupported) version of witness program.
    V14 = 14,
    /// Future (unsupported) version of witness program.
    V15 = 15,
    /// Future (unsupported) version of witness program.
    V16 = 16,
}

/// Prints [`WitnessVersion`] number (from 0 to 16) as integer, without
/// any prefix or suffix.
impl fmt::Display for WitnessVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", *self as u8) }
}

impl FromStr for WitnessVersion {
    type Err = WitnessVersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let version = s
            .parse()
            .map_err(|err| WitnessVersionError::UnparsableWitnessVersion(err))?;
        WitnessVersion::from_num(version)
    }
}

impl WitnessVersion {
    /// Converts 5-bit unsigned integer value matching single symbol from
    /// Bech32(m) address encoding ([`bech32::u5`]) into [`WitnessVersion`]
    /// variant.
    ///
    /// # Returns
    /// Version of the Witness program.
    ///
    /// # Errors
    /// If the integer does not correspond to any witness version, errors with
    /// [`Error::InvalidWitnessVersion`].
    pub fn from_u5(value: bech32::u5) -> Result<Self, WitnessVersionError> {
        WitnessVersion::from_num(value.to_u8())
    }

    /// Converts an 8-bit unsigned integer value into [`WitnessVersion`]
    /// variant.
    ///
    /// # Returns
    /// Version of the Witness program.
    ///
    /// # Errors
    /// If the integer does not correspond to any witness version, errors with
    /// [`Error::InvalidWitnessVersion`].
    pub fn from_num(no: u8) -> Result<Self, WitnessVersionError> {
        Ok(match no {
            0 => WitnessVersion::V0,
            1 => WitnessVersion::V1,
            2 => WitnessVersion::V2,
            3 => WitnessVersion::V3,
            4 => WitnessVersion::V4,
            5 => WitnessVersion::V5,
            6 => WitnessVersion::V6,
            7 => WitnessVersion::V7,
            8 => WitnessVersion::V8,
            9 => WitnessVersion::V9,
            10 => WitnessVersion::V10,
            11 => WitnessVersion::V11,
            12 => WitnessVersion::V12,
            13 => WitnessVersion::V13,
            14 => WitnessVersion::V14,
            15 => WitnessVersion::V15,
            16 => WitnessVersion::V16,
            wrong => Err(WitnessVersionError::InvalidWitnessVersion(wrong))?,
        })
    }

    /// Converts bitcoin script opcode into [`WitnessVersion`] variant.
    ///
    /// # Returns
    /// Version of the Witness program (for opcodes in range of
    /// `OP_0`..`OP_16`).
    ///
    /// # Errors
    /// If the opcode does not correspond to any witness version, errors with
    /// [`Error::MalformedWitnessVersion`].
    pub fn from_opcode(opcode: opcodes::All) -> Result<Self, WitnessVersionError> {
        match opcode.into_u8() {
            0 => Ok(WitnessVersion::V0),
            version
                if version >= opcodes::all::OP_PUSHNUM_1.into_u8()
                    && version <= opcodes::all::OP_PUSHNUM_16.into_u8() =>
            {
                WitnessVersion::from_num(version - opcodes::all::OP_PUSHNUM_1.into_u8() + 1)
            }
            _ => Err(WitnessVersionError::MalformedWitnessVersion),
        }
    }

    /// Converts bitcoin script [`Instruction`] (parsed opcode) into
    /// [`WitnessVersion`] variant.
    ///
    /// # Returns
    /// Version of the Witness program for [`Instruction::Op`] and
    /// [`Instruction::PushBytes`] with byte value within `1..=16` range.
    ///
    /// # Errors
    /// If the opcode does not correspond to any witness version, errors with
    /// [`Error::MalformedWitnessVersion`] for the rest of opcodes.
    pub fn from_instruction(instruction: Instruction) -> Result<Self, WitnessVersionError> {
        match instruction {
            Instruction::Op(op) => WitnessVersion::from_opcode(op),
            Instruction::PushBytes(bytes) if bytes.len() == 0 => Ok(WitnessVersion::V0),
            Instruction::PushBytes(_) => Err(WitnessVersionError::MalformedWitnessVersion),
        }
    }

    /// Returns integer version number representation for a given
    /// [`WitnessVersion`] value.
    ///
    /// NB: this is not the same as an integer representation of the opcode
    /// signifying witness version in bitcoin script. Thus, there is no
    /// function to directly convert witness version into a byte since the
    /// conversion requires context (bitcoin script or just a version number).
    pub fn into_num(self) -> u8 { self as u8 }

    /// Determines the checksum variant. See BIP-0350 for specification.
    pub fn bech32_variant(&self) -> bech32::Variant {
        match self {
            WitnessVersion::V0 => bech32::Variant::Bech32,
            _ => bech32::Variant::Bech32m,
        }
    }
}

impl From<WitnessVersion> for bech32::u5 {
    /// Converts [`WitnessVersion`] instance into corresponding Bech32(m)
    /// u5-value ([`bech32::u5`]).
    fn from(version: WitnessVersion) -> Self {
        bech32::u5::try_from_u8(version.into_num()).expect("WitnessVersion must be 0..=16")
    }
}

impl From<WitnessVersion> for opcodes::All {
    /// Converts [`WitnessVersion`] instance into corresponding Bitcoin
    /// scriptopcode (`OP_0`..`OP_16`).
    fn from(version: WitnessVersion) -> opcodes::All {
        match version {
            WitnessVersion::V0 => opcodes::all::OP_PUSHBYTES_0,
            no => opcodes::All::from(opcodes::all::OP_PUSHNUM_1.into_u8() + no.into_num() - 1),
        }
    }
}

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

    /// Computes witness version of the `pubkeyScript`
    pub fn witness_version(&self) -> Option<WitnessVersion> {
        if self.0.is_witness_program() {
            Some(
                WitnessVersion::from_opcode(opcodes::All::from(self.0[0]))
                    .expect("Script::is_witness_program is broken"),
            )
        } else {
            None
        }
    }
}

impl From<PubkeyHash> for PubkeyScript {
    fn from(pkh: PubkeyHash) -> Self { Script::new_p2pkh(&pkh).into() }
}

impl From<WPubkeyHash> for PubkeyScript {
    fn from(wpkh: WPubkeyHash) -> Self { Script::new_v0_wpkh(&wpkh).into() }
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
    pub fn to_p2wsh(&self) -> PubkeyScript { Script::new_v0_wsh(&self.script_hash()).into() }

    /// Generates [`PubkeyScript`] matching given `witnessScript` for legacy
    /// P2WSH-in-P2SH outputs.
    #[inline]
    pub fn to_p2sh_wsh(&self) -> PubkeyScript { RedeemScript::from(self.clone()).to_p2sh() }
}

impl From<WitnessScript> for RedeemScript {
    fn from(witness_script: WitnessScript) -> Self {
        RedeemScript(Script::new_v0_wsh(&witness_script.script_hash()))
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
    pub witness: Option<Vec<Vec<u8>>>,
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
                self.witness = Some(
                    self.sig_script
                        .as_inner()
                        .instructions_minimal()
                        .filter_map(|instr| {
                            if let Ok(Instruction::PushBytes(bytes)) = instr {
                                Some(bytes.to_vec())
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<Vec<u8>>>()
                        .into(),
                );
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
