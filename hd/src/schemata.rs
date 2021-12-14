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

//! Derivation schemata based on BIP-43-related standards.

use core::convert::TryInto;
use core::str::FromStr;
use std::convert::TryFrom;

use bitcoin::util::bip32;
use bitcoin::util::bip32::{ChildNumber, DerivationPath};
use miniscript::descriptor::DescriptorType;

use crate::{HardenedIndex, SegmentIndexes, UnhardenedIndex};

/// Errors in parsing derivation scheme string representation
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Error, Display)]
#[display(doc_comments)]
pub enum ParseError {
    /// invalid blockchain name {0}; it must be either `bitcoin`, `testnet` or
    /// hardened index number
    InvalidBlockchainName(String),

    /// LNPBP-43 blockchain index {0} must be hardened
    UnhardenedBlockchainIndex(u32),

    /// invalid LNPBP-43 identity representaiton {0}
    InvalidIdentityIndex(String),

    /// BIP-{0} support is not implemented (of BIP with this number does not
    /// exist)
    UnimplementedBip(u16),

    /// invalid BIP-43 custom derivation path
    InvalidCustomDerivation,

    /// BIP-48 scheme must have form of `bip48//<script_type>h`
    InvalidBip48Scheme,

    /// invalid LNPBP-43 derivation scheme encoding
    InvalidLnpBp43Scheme,

    /// invalid derivation path `{0}`
    InvalidDerivationPath(String),
}

/// Derivation path index specifying blockchain in LNPBP-43 format
#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub enum DerivationBlockchain {
    /// Bitcoin mainnet
    #[display("bitcoin")]
    Bitcoin,

    /// Any testnet blockchain
    #[display("testnet")]
    Testnet,

    /// Custom blockchain (non-testnet)
    #[display(inner)]
    #[from]
    Custom(HardenedIndex),
}

impl DerivationBlockchain {
    /// Returns derivation path segment child number corresponding to the given
    /// blockchain from LNPBP-43 standard
    #[inline]
    pub fn child_number(self) -> ChildNumber {
        match self {
            Self::Bitcoin => ChildNumber::Hardened { index: 0 },
            Self::Testnet => ChildNumber::Normal { index: 1 },
            Self::Custom(index) => index.into(),
        }
    }
}

impl FromStr for DerivationBlockchain {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parsed = ChildNumber::from_str(s);
        match (s.to_lowercase().as_str(), parsed) {
            ("bitcoin", _) => Ok(Self::Bitcoin),
            ("testnet", _) => Ok(Self::Testnet),
            (_, Ok(index @ ChildNumber::Hardened { .. })) => {
                Ok(Self::Custom(index.try_into().expect(
                    "ChildNumber::Hardened failed to convert into HardenedIndex type",
                )))
            }
            (_, Ok(ChildNumber::Normal { index })) => {
                Err(ParseError::UnhardenedBlockchainIndex(index))
            }
            (wrong, Err(_)) => Err(ParseError::InvalidBlockchainName(wrong.to_owned())),
        }
    }
}

/// Specific derivation scheme after BIP standards
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[cfg_attr(feature = "clap", derive(ArgEnum))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[non_exhaustive]
pub enum DerivationScheme {
    /// Account-based P2PKH derivation
    ///
    /// `m / 44' / coin_type' / account'`
    #[display("bip44", alt = "m/44h")]
    Bip44,

    /// Account-based native P2WPKH derivation
    ///
    /// `m / 84' / coin_type' / account'`
    #[display("bip84", alt = "m/84h")]
    Bip84,

    /// Account-based legacy P2WPH-in-P2SH derivation
    ///
    /// `m / 49' / coin_type' / account'`
    #[display("bip49", alt = "m/49h")]
    Bip49,

    /// Account-based single-key P2TR derivation
    ///
    /// `m / 86' / coin_type' / account'`
    #[display("bip86", alt = "m/86h")]
    Bip86,

    /// Cosigner-index-based multisig derivation
    ///
    /// `m / 45' / cosigner_index`
    #[display("bip45", alt = "m/45h")]
    Bip45,

    /// Account-based multisig derivation with sorted keys & P2WSH scripts
    /// (native or nested)
    ///
    /// `m / 48' / coin_type' / account' / script_type'`
    #[display("bip48//{script_type}", alt = "m/48h//{script_type}")]
    Bip48 {
        /// BIP-48 script type
        script_type: HardenedIndex,
    },

    /// Account- & descriptor-based derivation for multi-sig wallets
    #[display("bip87", alt = "m/87h")]
    ///
    /// `m / 87' / coin_type' / account'`
    Bip87,

    /// Identity & account-based universal derivation according to LNPBP-43
    ///
    /// `m / 443' / blockchain' / identity' / account'`
    #[display("lnpbp43//{identity}", alt = "m/443h//{identity}")]
    LnpBp43 {
        /// Identity number
        identity: HardenedIndex,
    },

    /// Generic BIP43 derivation with custom (non-standard) purpose value
    ///
    /// `m / purpose' / coin_type' / account'`
    #[display("m/{purpose}")]
    Bip43 {
        /// Purpose value
        purpose: HardenedIndex,
    },

    /// Custom (non-BIP-43) derivation path
    #[display("{derivation}")]
    Custom {
        /// Custom derivation path
        derivation: DerivationPath,
    },
}

impl FromStr for DerivationScheme {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_lowercase();
        let bip = s.strip_prefix("bip");
        let lnpbp43 = s.strip_prefix("lnpbp43");
        let path = s.strip_prefix("m/");
        Ok(match (bip, lnpbp43, path) {
            (Some("44"), ..) => DerivationScheme::Bip44,
            (Some("84"), ..) => DerivationScheme::Bip84,
            (Some("49"), ..) => DerivationScheme::Bip49,
            (Some("86"), ..) => DerivationScheme::Bip86,
            (Some("45"), ..) => DerivationScheme::Bip45,
            (Some("48//1h"), ..) | (Some("48//2h"), ..) => match s
                .strip_prefix("bip48//")
                .and_then(|index| HardenedIndex::from_str(index).ok())
            {
                Some(script_type) => DerivationScheme::Bip48 { script_type },
                None => return Err(ParseError::InvalidBip48Scheme),
            },
            (Some("87"), ..) => DerivationScheme::Bip87,
            (None, Some(_), _) => match s.strip_prefix("lnpbp43//") {
                Some(identity) => {
                    let identity = HardenedIndex::from_str(identity)
                        .map_err(|_| ParseError::InvalidIdentityIndex(identity.to_owned()))?;
                    DerivationScheme::LnpBp43 { identity }
                }
                None => return Err(ParseError::InvalidLnpBp43Scheme),
            },
            (None, None, Some(_)) => {
                let path: Vec<ChildNumber> = DerivationPath::from_str(&s)
                    .map_err(|_| ParseError::InvalidDerivationPath(s))?
                    .into();
                match path
                    .first()
                    .copied()
                    .ok_or(bip32::Error::InvalidChildNumberFormat)
                    .and_then(ChildNumber::try_into)
                {
                    Ok(_) if path.len() > 1 => DerivationScheme::Custom {
                        derivation: path.into(),
                    },
                    Err(_) => DerivationScheme::Custom {
                        derivation: path.into(),
                    },
                    Ok(purpose) => DerivationScheme::Bip43 { purpose },
                }
            }
            (_, _, _) => return Err(ParseError::InvalidCustomDerivation),
        })
    }
}

impl DerivationScheme {
    /// Reconstructs derivation scheme used by the provided derivation path
    pub fn from_derivation(derivation: &DerivationPath) -> DerivationScheme {
        let mut iter = derivation.into_iter();
        let first = iter.next().copied().map(HardenedIndex::try_from);
        let second = iter.next().copied().map(HardenedIndex::try_from);
        match (first, second) {
            (None, _) => DerivationScheme::Custom {
                derivation: none!(),
            },
            (Some(Ok(HardenedIndex(44))), _) => DerivationScheme::Bip44,
            (Some(Ok(HardenedIndex(84))), _) => DerivationScheme::Bip84,
            (Some(Ok(HardenedIndex(49))), _) => DerivationScheme::Bip49,
            (Some(Ok(HardenedIndex(86))), _) => DerivationScheme::Bip86,
            (Some(Ok(HardenedIndex(45))), _) => DerivationScheme::Bip45,
            (Some(Ok(HardenedIndex(87))), _) => DerivationScheme::Bip87,

            (Some(Ok(HardenedIndex(48))), Some(Ok(script_type))) => {
                DerivationScheme::Bip48 { script_type }
            }

            (Some(Ok(HardenedIndex(443))), Some(Ok(identity))) => {
                DerivationScheme::LnpBp43 { identity }
            }

            (Some(Ok(purpose)), _) => DerivationScheme::Bip43 { purpose },

            (Some(Err(_)), _) => DerivationScheme::Custom {
                derivation: derivation.clone(),
            },
        }
    }

    /// Get hardened index matching BIP-43 purpose value, if any
    pub fn purpose(&self) -> Option<HardenedIndex> {
        Some(match self {
            DerivationScheme::Bip44 => HardenedIndex(44),
            DerivationScheme::Bip84 => HardenedIndex(84),
            DerivationScheme::Bip49 => HardenedIndex(49),
            DerivationScheme::Bip86 => HardenedIndex(86),
            DerivationScheme::Bip45 => HardenedIndex(45),
            DerivationScheme::Bip48 { .. } => HardenedIndex(48),
            DerivationScheme::Bip87 => HardenedIndex(87),
            DerivationScheme::LnpBp43 { .. } => HardenedIndex(443),
            DerivationScheme::Bip43 { purpose } => *purpose,
            DerivationScheme::Custom { .. } => return None,
        })
    }

    /// Construct derivation path up to the provided account index segment
    pub fn to_account_derivation(
        &self,
        account_index: ChildNumber,
        blockchain: DerivationBlockchain,
    ) -> DerivationPath {
        let mut path = Vec::with_capacity(4);
        if let Some(purpose) = self.purpose() {
            path.push(purpose.into())
        }
        if let DerivationScheme::LnpBp43 { identity } = self {
            path.push(ChildNumber::from(*identity));
        }
        if let DerivationScheme::Custom { derivation } = self {
            path.extend(derivation);
        } else {
            path.push(blockchain.child_number());
            path.push(account_index);
        }
        path.into()
    }

    /// Construct full derivation path including address index and case
    /// (main, change etc)
    pub fn to_key_derivation(
        &self,
        account_index: ChildNumber,
        blockchain: DerivationBlockchain,
        index: UnhardenedIndex,
        case: Option<UnhardenedIndex>,
    ) -> DerivationPath {
        let mut derivation = self.to_account_derivation(account_index, blockchain);
        derivation = derivation.extend(&[index.into()]);
        derivation = case
            .map(|case| derivation.extend(&[case.into()]))
            .unwrap_or(derivation);
        derivation
    }

    /// Check whether provided descriptor type can be used with this derivation
    /// scheme
    pub fn check_descriptor_type(&self, descriptor_type: DescriptorType) -> bool {
        match (self, descriptor_type) {
            (DerivationScheme::Bip44, DescriptorType::Pkh)
            | (DerivationScheme::Bip84, DescriptorType::Wpkh)
            | (DerivationScheme::Bip49, DescriptorType::ShWpkh)
            // TODO: This must be DescriptorType::Tr with miniscript 7.0
            | (DerivationScheme::Bip86, DescriptorType::Bare)
            | (DerivationScheme::Bip45, DescriptorType::ShSortedMulti)
            | (DerivationScheme::Bip87, DescriptorType::ShSortedMulti)
            | (DerivationScheme::Bip87, DescriptorType::ShWshSortedMulti)
            | (DerivationScheme::Bip87, DescriptorType::WshSortedMulti) => true,
            (
                DerivationScheme::Bip48 { script_type },
                DescriptorType::ShWshSortedMulti,
            ) if script_type.first_index() == 1 => true,
            (
                DerivationScheme::Bip48 { script_type },
                DescriptorType::WshSortedMulti,
            ) if script_type.first_index() == 2 => true,
            (DerivationScheme::LnpBp43 { .. }, _) => true,
            (_, _) => false,
        }
    }
}
