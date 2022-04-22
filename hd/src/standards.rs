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

//! Derivation schemata based on BIP-43-related standards.

use core::convert::TryInto;
use core::str::FromStr;
use std::convert::TryFrom;

use bitcoin::util::bip32::{ChildNumber, DerivationPath};
#[cfg(feature = "miniscript")]
use miniscript::descriptor::DescriptorType;
use slip132::KeyApplication;

use crate::{HardenedIndex, HardenedIndexExpected, UnhardenedIndex};

/// Errors in parsing derivation scheme string representation
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Error, Display)]
#[display(doc_comments)]
pub enum ParseError {
    /// invalid blockchain name {0}; it must be either `bitcoin`, `testnet` or
    /// hardened index number
    InvalidBlockchainName(String),

    /// LNPBP-43 blockchain index {0} must be hardened
    UnhardenedBlockchainIndex(u32),

    /// invalid LNPBP-43 identity representation {0}
    InvalidIdentityIndex(String),

    /// invalid BIP-43 purpose {0}
    InvalidPurposeIndex(String),

    /// BIP-{0} support is not implemented (of BIP with this number does not
    /// exist)
    UnimplementedBip(u16),

    /// derivation path can't be recognized as one of BIP-43-based standards
    UnrecognizedBipScheme,

    /// BIP-43 scheme must have form of `bip43/<purpose>h`
    InvalidBip43Scheme,

    /// BIP-48 scheme must have form of `bip48-native` or `bip48-nested`
    InvalidBip48Scheme,

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
            Self::Testnet => ChildNumber::Hardened { index: 1 },
            Self::Custom(index) => index.into(),
        }
    }

    /// Tests whether given derivation blockchain is a testnet.
    pub fn is_testnet(self) -> bool { self == DerivationBlockchain::Testnet }
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

/// Specific derivation scheme after BIP-43 standards
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[cfg_attr(feature = "clap", derive(ArgEnum))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[non_exhaustive]
pub enum Bip43 {
    /// Account-based P2PKH derivation.
    ///
    /// `m / 44' / coin_type' / account'`
    #[display("bip44", alt = "m/44h")]
    Bip44,

    /// Account-based native P2WPKH derivation.
    ///
    /// `m / 84' / coin_type' / account'`
    #[display("bip84", alt = "m/84h")]
    Bip84,

    /// Account-based legacy P2WPH-in-P2SH derivation.
    ///
    /// `m / 49' / coin_type' / account'`
    #[display("bip49", alt = "m/49h")]
    Bip49,

    /// Account-based single-key P2TR derivation.
    ///
    /// `m / 86' / coin_type' / account'`
    #[display("bip86", alt = "m/86h")]
    Bip86,

    /// Cosigner-index-based multisig derivation.
    ///
    /// `m / 45' / cosigner_index
    #[display("bip45", alt = "m/45h")]
    Bip45,

    /// Account-based multisig derivation with sorted keys & P2WSH nested.
    /// scripts
    ///
    /// `m / 48' / coin_type' / account' / 1'`
    #[display("bip48-nested", alt = "m/48h//1h")]
    Bip48Nested,

    /// Account-based multisig derivation with sorted keys & P2WSH native.
    /// scripts
    ///
    /// `m / 48' / coin_type' / account' / 2'`
    #[display("bip48-native", alt = "m/48h//2h")]
    Bip48Native,

    /// Account- & descriptor-based derivation for multi-sig wallets.
    ///
    /// `m / 87' / coin_type' / account'`
    #[display("bip87", alt = "m/87h")]
    Bip87,

    /// Generic BIP43 derivation with custom (non-standard) purpose value.
    ///
    /// `m / purpose'`
    #[display("bip43/{purpose}")]
    Bip43 {
        /// Purpose value
        purpose: HardenedIndex,
    },
}

impl FromStr for Bip43 {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_lowercase();
        let bip = s.strip_prefix("bip").or_else(|| s.strip_prefix("m/"));
        Ok(match bip {
            Some("44") => Bip43::Bip44,
            Some("84") => Bip43::Bip84,
            Some("49") => Bip43::Bip49,
            Some("86") => Bip43::Bip86,
            Some("45") => Bip43::Bip45,
            Some(bip48) if bip48.starts_with("48//") => match s
                .strip_prefix("bip48//")
                .and_then(|index| HardenedIndex::from_str(index).ok())
            {
                Some(script_type) if script_type == 1u8 => Bip43::Bip48Nested,
                Some(script_type) if script_type == 2u8 => Bip43::Bip48Native,
                _ => return Err(ParseError::InvalidBip48Scheme),
            },
            Some("48-nested") => Bip43::Bip48Nested,
            Some("48-native") => Bip43::Bip48Native,
            Some("87") => Bip43::Bip87,
            None if s.starts_with("bip43") => match s.strip_prefix("bip43/") {
                Some(purpose) => {
                    let purpose = HardenedIndex::from_str(purpose)
                        .map_err(|_| ParseError::InvalidPurposeIndex(purpose.to_owned()))?;
                    Bip43::Bip43 { purpose }
                }
                None => return Err(ParseError::InvalidBip43Scheme),
            },
            Some(_) | None => return Err(ParseError::UnrecognizedBipScheme),
        })
    }
}

impl Bip43 {
    /// Constructs derivation standard corresponding to a single-sig P2PKH.
    pub fn singlesig_pkh() -> Bip43 { Bip43::Bip44 }
    /// Constructs derivation standard corresponding to a single-sig
    /// P2WPKH-in-P2SH.
    pub fn singlesig_nested0() -> Bip43 { Bip43::Bip49 }
    /// Constructs derivation standard corresponding to a single-sig P2WPKH.
    pub fn singlesig_segwit0() -> Bip43 { Bip43::Bip84 }
    /// Constructs derivation standard corresponding to a single-sig P2TR.
    pub fn singlelsig_taproot() -> Bip43 { Bip43::Bip86 }
    /// Constructs derivation standard corresponding to a multi-sig P2SH BIP45.
    pub fn multisig_ordered_sh() -> Bip43 { Bip43::Bip45 }
    /// Constructs derivation standard corresponding to a multi-sig sorted
    /// P2WSH-in-P2SH.
    pub fn multisig_nested0() -> Bip43 { Bip43::Bip48Nested }
    /// Constructs derivation standard corresponding to a multi-sig sorted
    /// P2WSH.
    pub fn multisig_segwit0() -> Bip43 { Bip43::Bip48Native }
    /// Constructs derivation standard corresponding to a multi-sig BIP87.
    pub fn multisig_descriptor() -> Bip43 { Bip43::Bip87 }
}

/// Methods for derivation standard enumeration types.
pub trait DerivationStandard: Eq + Clone {
    /// Deduces derivation standard used by the provided derivation path, if
    /// possible.
    fn deduce(derivation: &DerivationPath) -> Option<Self>
    where
        Self: Sized;

    /// Returns set of derivation standards corresponding to a given SLIP-132
    /// key application, if such is known.
    fn matching(slip: KeyApplication) -> Option<Self>
    where
        Self: Sized;

    /// Get hardened index matching BIP-43 purpose value, if any.
    fn purpose(&self) -> Option<HardenedIndex>;

    /// Depth of the account extended public key according to the given
    /// standard.
    ///
    /// Returns `None` if the standard does not provide information on
    /// account-level xpubs.
    fn account_depth(&self) -> Option<u8>;

    /// Depth of the derivation path defining `coin_type` key, i.e. the used
    /// blockchain.
    ///
    /// Returns `None` if the standard does not provide information on
    /// blockchain/coin type.
    fn coin_type_depth(&self) -> Option<u8>;

    /// Returns information whether the account xpub in this standard is the
    /// last hardened derivation path step, or there might be more hardened
    /// steps (like `script_type` in BIP-48).
    ///
    /// Returns `None` if the standard does not provide information on
    /// account-level xpubs.
    fn is_account_last_hardened(&self) -> Option<bool>;

    /// Extracts hardened index from a derivation path position defining coin
    /// type information (used blockchain), if present.
    ///
    /// # Returns
    ///
    /// - `None` if the standard does not define coin type information;
    /// - `HardenedIndexExpected` error if the coin type in the derivation path
    ///   was an unhardened index.
    /// - `Some(Ok(`[`HardenedIndex`]`))` with the coin type index otherwise.
    fn extract_coin_type(
        &self,
        path: &DerivationPath,
    ) -> Option<Result<HardenedIndex, HardenedIndexExpected>> {
        self.coin_type_depth()
            .and_then(|depth| path.as_ref().get(depth as usize))
            .copied()
            .map(HardenedIndex::try_from)
    }

    /// Extracts hardened index from a derivation path position defining account
    /// number, if present.
    ///
    /// # Returns
    ///
    /// - `None` if the standard does not define account number information;
    /// - `HardenedIndexExpected` error if the account number in the derivation
    ///   path was an unhardened index.
    /// - `Some(Ok(`[`HardenedIndex`]`))` with the account number index
    ///   otherwise.
    fn extract_account_index(
        &self,
        path: &DerivationPath,
    ) -> Option<Result<HardenedIndex, HardenedIndexExpected>> {
        self.account_depth()
            .and_then(|depth| path.as_ref().get(depth as usize))
            .copied()
            .map(HardenedIndex::try_from)
    }

    /// Construct derivation path for the account xpub.
    fn to_origin_derivation(&self, blockchain: DerivationBlockchain) -> DerivationPath;

    /// Construct derivation path up to the provided account index segment.
    fn to_account_derivation(
        &self,
        account_index: ChildNumber,
        blockchain: DerivationBlockchain,
    ) -> DerivationPath;

    /// Construct full derivation path including address index and case
    /// (main, change etc).
    fn to_key_derivation(
        &self,
        account_index: ChildNumber,
        blockchain: DerivationBlockchain,
        index: UnhardenedIndex,
        case: Option<UnhardenedIndex>,
    ) -> DerivationPath;

    /// Returns set of [`DescriptorType`] corresponding to the provided
    /// derivation standard. Can be an empty set.
    fn descriptor_types(&self) -> &'static [DescriptorType];

    /// Check whether provided descriptor type can be used with this derivation
    /// scheme.
    fn check_descriptor_type(&self, descriptor_type: DescriptorType) -> bool {
        self.descriptor_types()
            .iter()
            .any(|d| *d == descriptor_type)
    }

    /// Returns [`slip132::KeyApplication`] corresponding to the provided
    /// derivation standard.
    fn slip_application(&self) -> Option<slip132::KeyApplication>;

    /// Check whether provided descriptor type can be used with this derivation
    /// scheme.
    fn check_slip_application(&self, key_application: slip132::KeyApplication) -> bool {
        self.slip_application() == Some(key_application)
    }
}

impl DerivationStandard for Bip43 {
    fn deduce(derivation: &DerivationPath) -> Option<Bip43> {
        let mut iter = derivation.into_iter();
        let first = iter
            .next()
            .copied()
            .map(HardenedIndex::try_from)
            .transpose()
            .ok()??;
        let fourth = iter.nth(3).copied().map(HardenedIndex::try_from);
        Some(match (first, fourth) {
            (HardenedIndex(44), ..) => Bip43::Bip44,
            (HardenedIndex(84), ..) => Bip43::Bip84,
            (HardenedIndex(49), ..) => Bip43::Bip49,
            (HardenedIndex(86), ..) => Bip43::Bip86,
            (HardenedIndex(45), ..) => Bip43::Bip45,
            (HardenedIndex(87), ..) => Bip43::Bip87,
            (HardenedIndex(48), Some(Ok(script_type))) if script_type == 1u8 => Bip43::Bip48Nested,
            (HardenedIndex(48), Some(Ok(script_type))) if script_type == 2u8 => Bip43::Bip48Native,
            (HardenedIndex(48), _) => return None,
            (purpose, ..) => Bip43::Bip43 { purpose },
        })
    }

    fn matching(slip: KeyApplication) -> Option<Self> {
        Some(match slip {
            KeyApplication::Hashed => Bip43::Bip44,
            KeyApplication::SegWit => Bip43::Bip84,
            KeyApplication::SegWitMiltisig => Bip43::Bip48Native,
            KeyApplication::Nested => Bip43::Bip49,
            KeyApplication::NestedMultisig => Bip43::Bip48Nested,
            _ => return None,
        })
    }

    fn purpose(&self) -> Option<HardenedIndex> {
        Some(match self {
            Bip43::Bip44 => HardenedIndex(44),
            Bip43::Bip84 => HardenedIndex(84),
            Bip43::Bip49 => HardenedIndex(49),
            Bip43::Bip86 => HardenedIndex(86),
            Bip43::Bip45 => HardenedIndex(45),
            Bip43::Bip48Nested | Bip43::Bip48Native => HardenedIndex(48),
            Bip43::Bip87 => HardenedIndex(87),
            Bip43::Bip43 { purpose } => *purpose,
        })
    }

    fn account_depth(&self) -> Option<u8> {
        Some(match self {
            Bip43::Bip45 => return None,
            Bip43::Bip44
            | Bip43::Bip84
            | Bip43::Bip49
            | Bip43::Bip86
            | Bip43::Bip87
            | Bip43::Bip48Nested
            | Bip43::Bip48Native
            | Bip43::Bip43 { .. } => 3,
        })
    }

    fn coin_type_depth(&self) -> Option<u8> {
        Some(match self {
            Bip43::Bip45 => return None,
            Bip43::Bip44
            | Bip43::Bip84
            | Bip43::Bip49
            | Bip43::Bip86
            | Bip43::Bip87
            | Bip43::Bip48Nested
            | Bip43::Bip48Native
            | Bip43::Bip43 { .. } => 2,
        })
    }

    fn is_account_last_hardened(&self) -> Option<bool> {
        Some(match self {
            Bip43::Bip45 => false,
            Bip43::Bip44
            | Bip43::Bip84
            | Bip43::Bip49
            | Bip43::Bip86
            | Bip43::Bip87
            | Bip43::Bip43 { .. } => true,
            Bip43::Bip48Nested | Bip43::Bip48Native => false,
        })
    }

    fn to_origin_derivation(&self, blockchain: DerivationBlockchain) -> DerivationPath {
        let mut path = Vec::with_capacity(2);
        if let Some(purpose) = self.purpose() {
            path.push(purpose.into())
        }
        path.push(blockchain.child_number());
        path.into()
    }

    fn to_account_derivation(
        &self,
        account_index: ChildNumber,
        blockchain: DerivationBlockchain,
    ) -> DerivationPath {
        let mut path = Vec::with_capacity(2);
        path.push(account_index);
        if self == &Bip43::Bip48Native {
            path.push(HardenedIndex::from(2u8).into());
        } else if self == &Bip43::Bip48Nested {
            path.push(HardenedIndex::from(1u8).into());
        }
        let derivation = self.to_origin_derivation(blockchain);
        derivation.extend(&path);
        derivation
    }

    fn to_key_derivation(
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

    fn descriptor_types(&self) -> &'static [DescriptorType] {
        match self {
            Bip43::Bip44 => &[DescriptorType::Pkh],
            Bip43::Bip84 => &[DescriptorType::Wpkh],
            Bip43::Bip49 => &[DescriptorType::ShWpkh],
            Bip43::Bip86 => &[DescriptorType::Tr],
            Bip43::Bip45 => &[DescriptorType::ShSortedMulti],
            Bip43::Bip87 => &[
                DescriptorType::ShSortedMulti,
                DescriptorType::ShWshSortedMulti,
                DescriptorType::WshSortedMulti,
            ],
            Bip43::Bip48Nested => &[DescriptorType::ShWshSortedMulti],
            Bip43::Bip48Native => &[DescriptorType::WshSortedMulti],
            Bip43::Bip43 { .. } => &[
                DescriptorType::ShSortedMulti,
                DescriptorType::ShWshSortedMulti,
                DescriptorType::WshSortedMulti,
                DescriptorType::Tr,
            ],
        }
    }

    fn slip_application(&self) -> Option<slip132::KeyApplication> {
        Some(match self {
            Bip43::Bip44 => slip132::KeyApplication::Hashed,
            Bip43::Bip45 => return None,
            Bip43::Bip48Nested => slip132::KeyApplication::NestedMultisig,
            Bip43::Bip48Native => slip132::KeyApplication::SegWitMiltisig,
            Bip43::Bip49 => slip132::KeyApplication::Nested,
            Bip43::Bip84 => slip132::KeyApplication::SegWit,
            Bip43::Bip86 => return None,
            Bip43::Bip87 => return None,
            Bip43::Bip43 { .. } => return None,
        })
    }
}

#[cfg(not(feature = "miniscript"))]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum DescriptorType {
    /// Bare descriptor(Contains the native P2pk)
    Bare,
    /// Pure Sh Descriptor. Does not contain nested Wsh/Wpkh
    Sh,
    /// Pkh Descriptor
    Pkh,
    /// Wpkh Descriptor
    Wpkh,
    /// Wsh
    Wsh,
    /// Sh Wrapped Wsh
    ShWsh,
    /// Sh wrapped Wpkh
    ShWpkh,
    /// Sh Sorted Multi
    ShSortedMulti,
    /// Wsh Sorted Multi
    WshSortedMulti,
    /// Sh Wsh Sorted Multi
    ShWshSortedMulti,
    /// Tr Descriptor
    Tr,
}
