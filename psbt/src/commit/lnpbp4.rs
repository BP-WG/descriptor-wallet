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

use amplify::Slice32;
use bitcoin::hashes::Hash;
use commit_verify::lnpbp4;
use commit_verify::lnpbp4::{Message, ProtocolId};
use strict_encoding::{StrictDecode, StrictEncode};

use crate::{Output, ProprietaryKey, Psbt};

/// PSBT proprietary key prefix used for LNPBP4 commitment-related data.
pub const PSBT_LNPBP4_PREFIX: &[u8] = b"LNPBP4";

/// Proprietary key subtype for storing LNPBP4 information about each specific
/// protocol.
pub const PSBT_GLOBAL_LNPBP4_PROTOCOL_INFO: u8 = 0x00;

/// Proprietary key subtype for storing LNPBP4 single commitment message under
/// some protocol in global map.
pub const PSBT_OUT_LNPBP4_MESSAGE: u8 = 0x00;
/// Proprietary key subtype for storing LNPBP4 entropy constant.
pub const PSBT_OUT_LNPBP4_ENTROPY: u8 = 0x01;
/// Proprietary key subtype for storing LNPBP4 requirement for a minimal tree
/// size.
pub const PSBT_OUT_LNPBP4_MIN_TREE_DEPTH: u8 = 0x02;

/// Extension trait for static functions returning LNPBP4-related proprietary
/// keys.
pub trait ProprietaryKeyLnpbp4 {
    fn lnpbp4_message(protocol_id: ProtocolId) -> ProprietaryKey;
    fn lnpbp4_entropy() -> ProprietaryKey;
    fn lnpbp4_min_tree_depth() -> ProprietaryKey;
    fn lnpbp4_protocol_info(protocol_id: ProtocolId) -> ProprietaryKey;
}

impl ProprietaryKeyLnpbp4 for ProprietaryKey {
    /// Constructs [`PSBT_OUT_LNPBP4_MESSAGE`] proprietary key.
    fn lnpbp4_message(protocol_id: ProtocolId) -> ProprietaryKey {
        ProprietaryKey {
            prefix: PSBT_LNPBP4_PREFIX.to_vec(),
            subtype: PSBT_OUT_LNPBP4_MESSAGE,
            key: protocol_id.to_vec(),
        }
    }

    /// Constructs [`PSBT_OUT_LNPBP4_ENTROPY`] proprietary key.
    fn lnpbp4_entropy() -> ProprietaryKey {
        ProprietaryKey {
            prefix: PSBT_LNPBP4_PREFIX.to_vec(),
            subtype: PSBT_OUT_LNPBP4_ENTROPY,
            key: empty!(),
        }
    }

    /// Constructs [`PSBT_OUT_LNPBP4_MIN_TREE_DEPTH`] proprietary key.
    fn lnpbp4_min_tree_depth() -> ProprietaryKey {
        ProprietaryKey {
            prefix: PSBT_LNPBP4_PREFIX.to_vec(),
            subtype: PSBT_OUT_LNPBP4_MIN_TREE_DEPTH,
            key: empty!(),
        }
    }

    /// Constructs [`PSBT_GLOBAL_LNPBP4_PROTOCOL_INFO`] proprietary key.
    fn lnpbp4_protocol_info(protocol_id: ProtocolId) -> ProprietaryKey {
        ProprietaryKey {
            prefix: PSBT_LNPBP4_PREFIX.to_vec(),
            subtype: PSBT_GLOBAL_LNPBP4_PROTOCOL_INFO,
            key: protocol_id.to_vec(),
        }
    }
}

/// Errors processing LNPBP4-related proprietary PSBT keys and their values.
#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error, From
)]
#[display(doc_comments)]
pub enum Lnpbp4KeyError {
    /// The key contains invalid value
    #[from(strict_encoding::Error)]
    #[from(bitcoin::hashes::Error)]
    InvalidKeyValue,

    /// The key is already present, but has a different value
    AlreadySet,
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default)]
#[derive(StrictEncode, StrictDecode)]
pub struct Lnpbp4Info {
    pub hash_tag: Option<String>,
    pub inner_id: Option<Slice32>,
}

/// Extension trait for [`Psbt`] for working with proprietary LNPBP4 keys.
impl Psbt {
    /// Returns an information about the given LNPBP4 [`ProtocolId`], if any.
    ///
    /// # Errors
    ///
    /// If the key is present, but it's value can't be deserialized as a valid
    /// protocol information block.
    pub fn lnpbp4_protocol_info(
        &self,
        protocol_id: ProtocolId,
    ) -> Result<Lnpbp4Info, Lnpbp4KeyError> {
        let key = ProprietaryKey::lnpbp4_protocol_info(protocol_id);
        Ok(self
            .proprietary
            .get(&key)
            .map(Lnpbp4Info::strict_deserialize)
            .transpose()?
            .unwrap_or_default())
    }

    /// Adds LNPBP4 protocol information.
    ///
    /// # Returns
    ///
    /// `true`, if the protocol information was successfully added, `false` if
    /// it was already present.
    ///
    /// # Errors
    ///
    /// If the key for the given [`ProtocolId`] is already present and the
    /// information was different.
    pub fn set_lnpbp4_protocol_info(
        &mut self,
        protocol_id: ProtocolId,
        hash_tag: Option<String>,
        inner_id: Option<Slice32>,
    ) -> Result<bool, Lnpbp4KeyError> {
        let key = ProprietaryKey::lnpbp4_protocol_info(protocol_id);
        let val = Lnpbp4Info { hash_tag, inner_id }
            .strict_serialize()
            .expect("memory serializer should not fail");
        if let Some(v) = self.proprietary.get(&key) {
            if v != &val {
                return Err(Lnpbp4KeyError::InvalidKeyValue);
            }
            return Ok(false);
        }
        self.proprietary.insert(key, val);
        Ok(true)
    }
}

/// Extension trait for [`Output`] for working with proprietary LNPBP4
/// keys.
impl Output {
    /// Returns [`lnpbp4::MessageMap`] constructed from the proprietary key
    /// data.
    pub fn lnpbp4_message_map(&self) -> Result<lnpbp4::MessageMap, Lnpbp4KeyError> {
        self.proprietary
            .iter()
            .filter(|(key, _)| {
                key.prefix == PSBT_LNPBP4_PREFIX && key.subtype == PSBT_OUT_LNPBP4_MESSAGE
            })
            .map(|(key, val)| {
                Ok((
                    ProtocolId::from_slice(&key.key).ok_or(Lnpbp4KeyError::InvalidKeyValue)?,
                    Message::from_slice(val).map_err(|_| Lnpbp4KeyError::InvalidKeyValue)?,
                ))
            })
            .collect()
    }

    /// Returns a valid LNPBP-4 [`Message`] associated with the given
    /// [`ProtocolId`], if any.
    ///
    /// # Errors
    ///
    /// If the key is present, but it's value can't be deserialized as a valid
    /// [`Message`].
    pub fn lnpbp4_message(
        &self,
        protocol_id: ProtocolId,
    ) -> Result<Option<Message>, Lnpbp4KeyError> {
        let key = ProprietaryKey::lnpbp4_message(protocol_id);
        self.proprietary
            .get(&key)
            .map(Message::strict_deserialize)
            .transpose()
            .map_err(Lnpbp4KeyError::from)
    }

    /// Returns a valid LNPBP-4 entropy value, if present.
    ///
    /// # Errors
    ///
    /// If the key is present, but it's value can't be deserialized as a valid
    /// entropy value.
    pub fn lnpbp4_entropy(&self) -> Result<Option<u64>, Lnpbp4KeyError> {
        let key = ProprietaryKey::lnpbp4_entropy();
        self.proprietary
            .get(&key)
            .map(u64::strict_deserialize)
            .transpose()
            .map_err(Lnpbp4KeyError::from)
    }

    /// Returns a valid LNPBP-4 minimal tree depth value, if present.
    ///
    /// # Errors
    ///
    /// If the key is present, but it's value can't be deserialized as a valid
    /// minimal tree depth value.
    pub fn lnpbp4_min_tree_depth(&self) -> Result<Option<u8>, Lnpbp4KeyError> {
        let key = ProprietaryKey::lnpbp4_min_tree_depth();
        self.proprietary
            .get(&key)
            .map(u8::strict_deserialize)
            .transpose()
            .map_err(Lnpbp4KeyError::from)
    }

    /// Sets LNPBP4 [`Message`] for the given [`ProtocolId`].
    ///
    /// # Returns
    ///
    /// `true`, if the message was set successfully, `false` if this message was
    /// already present for this protocol.
    ///
    /// # Errors
    ///
    /// If the key for the given [`ProtocolId`] is already present and the
    /// message is different.
    pub fn set_lnpbp4_message(
        &mut self,
        protocol_id: ProtocolId,
        message: Message,
    ) -> Result<bool, Lnpbp4KeyError> {
        let key = ProprietaryKey::lnpbp4_message(protocol_id);
        let val = message
            .strict_serialize()
            .expect("memory serializer should not fail");
        if let Some(v) = self.proprietary.get(&key) {
            if v != &val {
                return Err(Lnpbp4KeyError::InvalidKeyValue);
            }
            return Ok(false);
        }
        self.proprietary.insert(key, val);
        Ok(true)
    }

    /// Sets LNPBP4 entropy value.
    ///
    /// # Returns
    ///
    /// `true`, if the entropy was set successfully, `false` if this entropy
    /// value was already set.
    ///
    /// # Errors
    ///
    /// If the entropy was already set with a different value than the provided
    /// one.
    pub fn set_lnpbp4_entropy(&mut self, entropy: u64) -> Result<bool, Lnpbp4KeyError> {
        let key = ProprietaryKey::lnpbp4_entropy();
        let val = entropy
            .strict_serialize()
            .expect("memory serializer should not fail");
        if let Some(v) = self.proprietary.get(&key) {
            if v != &val {
                return Err(Lnpbp4KeyError::InvalidKeyValue);
            }
            return Ok(false);
        }
        self.proprietary.insert(key, val);
        Ok(true)
    }

    /// Sets LNPBP4 min tree depth value.
    ///
    /// # Returns
    ///
    /// Previous minimal tree depth value, if it was present and valid - or None
    /// if the value was absent or invalid (the new value is still assigned).
    pub fn set_lnpbp4_min_tree_depth(&mut self, min_depth: u8) -> Option<u8> {
        let key = ProprietaryKey::lnpbp4_min_tree_depth();
        let val = min_depth
            .strict_serialize()
            .expect("memory serializer should not fail");
        self.proprietary
            .insert(key, val)
            .and_then(|v| u8::strict_deserialize(v).ok())
    }
}
