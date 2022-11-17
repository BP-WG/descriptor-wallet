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

//! Processing proprietary PSBT keys related to taproot-based OP_RETURN
//! (or tapret) commitments.
//!
//! NB: Wallets supporting tapret commitments must do that through the use of
//! deterministic bitcoin commitments crate (`bp-dpc`) in order to ensure
//! that multiple protocols can put commitment inside the same transaction
//! without collisions between them.
//!
//! This module provides support for marking PSBT outputs which may host
//! tapreturn commitment and populating PSBT with the data related to tapret
//! commitments.

use amplify::Slice32;
use bitcoin_scripts::taproot::DfsPath;
use confined_encoding::{ConfinedDecode, ConfinedEncode};

use crate::raw::ProprietaryKey;
use crate::Output;

/// PSBT proprietary key prefix used for tapreturn commitment.
pub const PSBT_TAPRET_PREFIX: &[u8] = b"TAPRET";

/// Proprietary key subtype for PSBT inputs containing the applied tapret tweak
/// information.
pub const PSBT_IN_TAPRET_TWEAK: u8 = 0x00;

/// Proprietary key subtype marking PSBT outputs which may host tapreturn
/// commitment.
pub const PSBT_OUT_TAPRET_HOST: u8 = 0x00;
/// Proprietary key subtype holding 32-byte commitment which will be put into
/// tapreturn tweak.
pub const PSBT_OUT_TAPRET_COMMITMENT: u8 = 0x01;
/// Proprietary key subtype holding merkle branch path to tapreturn tweak inside
/// the taptree structure.
pub const PSBT_OUT_TAPRET_PROOF: u8 = 0x02;

/// Extension trait for static functions returning tapreturn-related proprietary
/// keys.
pub trait ProprietaryKeyTapret {
    /// Constructs [`PSBT_IN_TAPRET_TWEAK`] proprietary key.
    fn tapret_tweak() -> ProprietaryKey {
        ProprietaryKey {
            prefix: PSBT_TAPRET_PREFIX.to_vec(),
            subtype: PSBT_IN_TAPRET_TWEAK,
            key: vec![],
        }
    }

    /// Constructs [`PSBT_OUT_TAPRET_HOST`] proprietary key.
    fn tapret_host() -> ProprietaryKey {
        ProprietaryKey {
            prefix: PSBT_TAPRET_PREFIX.to_vec(),
            subtype: PSBT_OUT_TAPRET_HOST,
            key: vec![],
        }
    }

    /// Constructs [`PSBT_OUT_TAPRET_COMMITMENT`] proprietary key.
    fn tapret_commitment() -> ProprietaryKey {
        ProprietaryKey {
            prefix: PSBT_TAPRET_PREFIX.to_vec(),
            subtype: PSBT_OUT_TAPRET_COMMITMENT,
            key: vec![],
        }
    }

    /// Constructs [`PSBT_OUT_TAPRET_PROOF`] proprietary key.
    fn tapret_proof() -> ProprietaryKey {
        ProprietaryKey {
            prefix: PSBT_TAPRET_PREFIX.to_vec(),
            subtype: PSBT_OUT_TAPRET_PROOF,
            key: vec![],
        }
    }
}

impl ProprietaryKeyTapret for ProprietaryKey {}

/// Errors processing tapret-related proprietary PSBT keys and their values.
#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error, From
)]
#[display(doc_comments)]
pub enum TapretKeyError {
    /// output already contains commitment; there must be a single commitment
    /// per output.
    OutputAlreadyHasCommitment,

    /// the output is not marked to host tapret commitments. Please first set
    /// PSBT_OUT_TAPRET_HOST flag.
    TapretProhibited,

    /// The key contains invalid value
    #[from(confined_encoding::Error)]
    InvalidKeyValue,
}

/// Error decoding [`DfsPath`] inside PSBT data
#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error
)]
#[display("incorrect DFS path data inside PSBT proprietary key value")]
pub struct DfsPathEncodeError;

impl Output {
    /// Returns whether this output may contain tapret commitment. This is
    /// detected by the presence of [`PSBT_OUT_TAPRET_HOST`] key.
    #[inline]
    pub fn is_tapret_host(&self) -> bool {
        self.proprietary
            .contains_key(&ProprietaryKey::tapret_host())
    }

    /// Returns information on the specific path within taproot script tree
    /// which is allowed as a place for tapret commitment. The path is taken
    /// from [`PSBT_OUT_TAPRET_HOST`] key.
    ///
    /// # Returns
    ///
    /// A value of the [`PSBT_OUT_TAPRET_HOST`] key, if present, or `None`
    /// otherwise. The value is deserialized from the key value data, and if
    /// the serialization fails a `Some(Err(`[`DfsPathEncodeError`]`))` is
    /// returned.
    pub fn tapret_dfs_path(&self) -> Option<Result<DfsPath, DfsPathEncodeError>> {
        self.proprietary
            .get(&ProprietaryKey::tapret_host())
            .map(|data| DfsPath::confined_deserialize(data).map_err(|_| DfsPathEncodeError))
    }

    /// Sets information on the specific path within taproot script tree which
    /// is allowed as a place for tapret commitment. The path is put into
    /// [`PSBT_OUT_TAPRET_HOST`] key.
    ///
    /// # Errors
    ///
    /// Errors with [`TapretKeyError::OutputAlreadyHasCommitment`] if the
    /// commitment is already present in the output.
    pub fn set_tapret_dfs_path(&mut self, path: &DfsPath) -> Result<(), TapretKeyError> {
        if self.tapret_dfs_path().is_some() {
            return Err(TapretKeyError::OutputAlreadyHasCommitment);
        }

        self.proprietary.insert(
            ProprietaryKey::tapret_host(),
            path.confined_serialize()
                .expect("DFS paths are always compact and serializable"),
        );

        Ok(())
    }

    /// Detects presence of a valid [`PSBT_OUT_TAPRET_COMMITMENT`].
    ///
    /// If [`PSBT_OUT_TAPRET_COMMITMENT`] is absent or its value is invalid,
    /// returns `false`. In the future, when `PSBT_OUT_TAPRET_COMMITMENT` will
    /// become a standard and non-custom key, PSBTs with invalid key values
    /// will error at deserialization and this function will return `false`
    /// only in cases when the output does not have
    /// `PSBT_OUT_TAPRET_COMMITMENT`.
    pub fn has_tapret_commitment(&self) -> bool {
        self.proprietary
            .contains_key(&ProprietaryKey::tapret_commitment())
    }

    /// Returns valid tapret commitment from the [`PSBT_OUT_TAPRET_COMMITMENT`]
    /// key, if present. If the commitment is absent or invalid, returns
    /// `None`.
    ///
    /// We do not error on invalid commitments in order to support future update
    /// of this proprietary key to the standard one. In this case, the
    /// invalid commitments (having non-32 bytes) will be filtered at the
    /// moment of PSBT deserialization and this function will return `None`
    /// only in situations when the commitment is absent.
    pub fn tapret_commitment(&self) -> Option<Slice32> {
        self.proprietary
            .get(&ProprietaryKey::tapret_commitment())
            .and_then(Slice32::from_slice)
    }

    /// Assigns value of the tapreturn commitment to this PSBT output, by
    /// adding [`PSBT_OUT_TAPRET_COMMITMENT`] and [`PSBT_OUT_TAPRET_PROOF`]
    /// proprietary keys containing the 32-byte commitment as its proof.
    ///
    /// # Errors
    ///
    /// Errors with [`TapretKeyError::OutputAlreadyHasCommitment`] if the
    /// commitment is already present in the output, and with
    /// [`TapretKeyError::TapretProhibited`] if tapret commitments are not
    /// enabled for this output.
    pub fn set_tapret_commitment(
        &mut self,
        commitment: impl Into<[u8; 32]>,
        proof: &impl ConfinedEncode,
    ) -> Result<(), TapretKeyError> {
        if !self.is_tapret_host() {
            return Err(TapretKeyError::TapretProhibited);
        }

        if self.has_tapret_commitment() {
            return Err(TapretKeyError::OutputAlreadyHasCommitment);
        }

        self.proprietary.insert(
            ProprietaryKey::tapret_commitment(),
            commitment.into().to_vec(),
        );

        self.proprietary
            .insert(ProprietaryKey::tapret_proof(), proof.confined_serialize()?);

        Ok(())
    }

    /// Detects presence of a valid [`PSBT_OUT_TAPRET_PROOF`].
    ///
    /// If [`PSBT_OUT_TAPRET_PROOF`] is absent or its value is invalid,
    /// returns `false`. In the future, when `PSBT_OUT_TAPRET_PROOF` will
    /// become a standard and non-custom key, PSBTs with invalid key values
    /// will error at deserialization and this function will return `false`
    /// only in cases when the output does not have `PSBT_OUT_TAPRET_PROOF`.
    pub fn has_tapret_proof(&self) -> bool {
        self.proprietary
            .contains_key(&ProprietaryKey::tapret_proof())
    }

    /// Returns valid tapret commitment proof from the [`PSBT_OUT_TAPRET_PROOF`]
    /// key, if present. If the commitment is absent or invalid, returns `None`.
    ///
    /// We do not error on invalid proofs in order to support future update of
    /// this proprietary key to the standard one. In this case, the invalid
    /// commitments (having non-32 bytes) will be filtered at the moment of PSBT
    /// deserialization and this function will return `None` only in situations
    /// when the commitment is absent.
    ///
    /// Function returns generic type since the real type will create dependency
    /// on `bp-dpc` crate, which will result in circular dependency with the
    /// current crate.
    pub fn tapret_proof<T>(&self) -> Result<Option<T>, TapretKeyError>
    where
        T: ConfinedDecode,
    {
        self.proprietary
            .get(&ProprietaryKey::tapret_proof())
            .map(T::confined_deserialize)
            .transpose()
            .map_err(TapretKeyError::from)
    }
}
