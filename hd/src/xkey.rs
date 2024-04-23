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
use std::io::Write;
use std::str::FromStr;

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, Secp256k1, VerifyOnly};
use bitcoin::util::bip32;
use bitcoin::util::bip32::{ChainCode, ChildNumber, DerivationPath, ExtendedPubKey, Fingerprint};
use bitcoin::XpubIdentifier;
use slip132::{DefaultResolver, FromSlip132, KeyVersion};

use crate::{DerivationStandard, HardenedIndex, SegmentIndexes, UnhardenedIndex};

/// Errors constructing [`XpubOrigin`].
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum XpubRequirementError {
    /// The provided extended public key can't be used under the required
    /// derivation standard. The public key is suitable for {actual_standard}
    /// derivations, while a key for {required_standard} is needed.
    StandardMismatch {
        /// Actual data, not matching required data
        actual_standard: String,
        /// Required data
        required_standard: String,
    },

    /// The provided extended public key has a derivation depth {actual_depth},
    /// which is less than the depth of account-level key {required_depth}
    /// according to {standard}.
    ShallowKey {
        /// Actual data, not matching required data
        required_depth: u8,
        /// Required data
        actual_depth: u8,
        /// Used standard
        standard: String,
    },

    /// Extended public key is invalid for the provided requirements.
    /// Specifically, network information in BIP-32 data ({bip_network}) does
    /// not match network information encoded in SLIP-132 key version prefix
    /// ({slip_network}).
    NetworkMismatch {
        /// Network defined by a SLIP pubkey
        slip_network: bitcoin::Network,
        /// Network defined by a BIP32 data
        bip_network: bitcoin::Network,
    },

    /// Extended public key was created for the different bitcoin network than
    /// the wallet.
    TestnetMismatch {
        /** Is testnet expected? */
        expected: bool,
        /** Is testnet used? */
        actual: bool,
    },

    /// The given key is an account key according to the provided standard {0},
    /// however it uses a non-hardened derivation index {1}.
    UnhardenedAccountKey(String, UnhardenedIndex),
}

/// Errors happening when used derivation does not match one requried by a
/// standard.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum NonStandardDerivation {
    /// the given key is invalid or the derivation path is invalid due to
    /// account-level key being derived at non-hardened index {0}.
    UnhardenedAccount(UnhardenedIndex),

    /// non-standard derivation path with coin type being a non-hardened index
    /// {0}.
    UnhardenedCoinType(UnhardenedIndex),
}

/// Deterministic part of the extended public key descriptor
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct XpubkeyCore {
    /// Public key
    pub public_key: secp256k1::PublicKey,
    /// BIP32 chain code used for hierarchical derivation
    pub chain_code: ChainCode,
}

impl Display for XpubkeyCore {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { Display::fmt(&self.fingerprint(), f) }
}

impl From<ExtendedPubKey> for XpubkeyCore {
    fn from(xpub: ExtendedPubKey) -> Self {
        XpubkeyCore {
            public_key: xpub.public_key,
            chain_code: xpub.chain_code,
        }
    }
}

impl XpubkeyCore {
    /// Computes [`XpubIdentifier`] of the key
    pub fn identifier(&self) -> XpubIdentifier {
        XpubIdentifier::hash(&self.public_key.serialize())
    }

    /// Computes [`Fingerprint`] of the key
    pub fn fingerprint(&self) -> Fingerprint { Fingerprint::from(&self.identifier()[0..4]) }
}

#[cfg(feature = "miniscript")]
impl miniscript::MiniscriptKey for XpubkeyCore {
    type Sha256 = Self;
    type Hash256 = Self;
    type Ripemd160 = Self;
    type Hash160 = Self;
}

impl XpubkeyCore {
    /// Derives public key for a given terminal path
    pub fn derive(
        self,
        secp: &Secp256k1<VerifyOnly>,
        terminal: impl IntoIterator<Item = UnhardenedIndex>,
    ) -> PublicKey {
        let xpub = ExtendedPubKey {
            network: bitcoin::Network::Bitcoin,
            depth: 0,
            parent_fingerprint: zero!(),
            child_number: ChildNumber::Normal { index: 0 },
            public_key: self.public_key,
            chain_code: self.chain_code,
        };
        let xpub = xpub
            .derive_pub(
                secp,
                &terminal
                    .into_iter()
                    .map(|i| i.first_index())
                    .map(|index| ChildNumber::Normal { index })
                    .collect::<Vec<_>>(),
            )
            .expect("unhardened derivation failure");
        xpub.public_key
    }
}

/// Structure describing origin of some extended key
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct XpubOrigin<Standard>
where
    Standard: DerivationStandard,
{
    /// Is a key can be used only in testnet environment?
    pub testnet: bool,
    /// Master fingerprint, if known
    pub master_fingerprint: Option<Fingerprint>,
    /// Used derivation standard, if known
    pub standard: Option<Standard>,
    /// Account-level hardened derivation index, if known
    pub account: Option<HardenedIndex>,
}

impl<Standard> XpubOrigin<Standard>
where
    Standard: DerivationStandard + ToString,
{
    /// Constructs origin information for _an account_-level xpub or deeper key,
    /// extracting it from both `xpub` and SLIP132 key version (prefix) data.
    /// Ensures consistency of this information and returns error indicating
    /// discovered inconsistency.
    ///
    /// Compares the following correspondences between xpub and SLIP132-encoded
    /// key version:
    /// - network (testnet/mainnet only, since SLIP132 does not cover more
    ///   networks for bitcoin);
    /// - specific BIP43-based derivation standard matching the possible use of
    ///   the extended public key as an account-level key or deeper; basing on
    ///   its depth and child number;
    /// - if the xpub depth matches account key depth defined by the provided
    ///   derivation standard information, the child number of the xpub must be
    ///   a hardened number.
    ///
    /// Also checks that if there is a provided SLIP132 key version and
    /// derivation standard, they do match.
    pub fn with(
        master_fingerprint: Option<Fingerprint>,
        xpub: ExtendedPubKey,
        standard: Option<Standard>,
        slip: Option<KeyVersion>,
    ) -> Result<XpubOrigin<Standard>, XpubRequirementError> {
        let application = slip
            .as_ref()
            .and_then(KeyVersion::application::<DefaultResolver>);
        let standard_slip = application.and_then(Standard::matching);

        match (&standard, &standard_slip) {
            (Some(bip43), Some(slip)) if bip43 != slip => {
                return Err(XpubRequirementError::StandardMismatch {
                    actual_standard: slip.to_string(),
                    required_standard: bip43.to_string(),
                });
            }
            _ => {}
        }

        match slip
            .as_ref()
            .and_then(KeyVersion::network::<DefaultResolver>)
        {
            Some(slip_network) if slip_network != xpub.network => {
                return Err(XpubRequirementError::NetworkMismatch {
                    slip_network,
                    bip_network: xpub.network,
                });
            }
            _ => {}
        }

        let account_depth = standard_slip
            .as_ref()
            .and_then(DerivationStandard::account_depth);
        let account = match (&standard_slip, account_depth) {
            (Some(standard_slip), Some(required_depth)) if xpub.depth < required_depth => {
                return Err(XpubRequirementError::ShallowKey {
                    required_depth,
                    actual_depth: xpub.depth,
                    standard: standard_slip.to_string(),
                });
            }
            (Some(standard_slip), _) => {
                Some(HardenedIndex::try_from(xpub.child_number).map_err(|err| {
                    XpubRequirementError::UnhardenedAccountKey(standard_slip.to_string(), err.0)
                })?)
            }
            _ => None,
        };

        Ok(XpubOrigin {
            testnet: xpub.network == bitcoin::Network::Bitcoin,
            master_fingerprint,
            standard: standard.or(standard_slip),
            account,
        })
    }

    pub(crate) fn with_unchecked(
        master_fingerprint: Option<Fingerprint>,
        xpub: ExtendedPubKey,
        standard: Option<Standard>,
        slip: Option<KeyVersion>,
    ) -> XpubOrigin<Standard> {
        let application = slip
            .as_ref()
            .and_then(KeyVersion::application::<DefaultResolver>);
        let standard_slip = application.and_then(Standard::matching);

        let account = HardenedIndex::try_from(xpub.child_number).ok();

        XpubOrigin {
            testnet: xpub.network == bitcoin::Network::Bitcoin,
            master_fingerprint,
            standard: standard.or(standard_slip),
            account,
        }
    }

    /// Deduces key origin information, using derivation path, internal key
    /// metadata and optional SLIP132 version prefix.
    ///
    /// # Returns
    ///
    /// The function ensures that the derivation path matches the standard which
    /// is defined by SLIP132, if the slip information is provided, and errors
    /// with [`NonStandardDerivation`] otherwise. This "extenral" error returned
    /// by the function may indicate the internal inconsistency in the program
    /// logic and can be `expect`'ed in this case.
    ///
    /// The function also checks the key and SLIP132 data for the internal
    /// consistency using [`XpubOrigin::with`] method, and returns
    /// `Ok(`[`XpubRequirementError`]`)` if this check fails. It also checks
    /// that the provided derivation path coin type index matches the network
    /// specified by the SLIP132 and xpub data, also returning
    /// `Ok(`[`XpubRequirementError`]`)` if this check fails. These errors
    /// should not be ignored.
    pub fn deduce(
        master_fingerprint: Option<Fingerprint>,
        source: &DerivationPath,
        xpub: ExtendedPubKey,
        slip: Option<KeyVersion>,
    ) -> Result<Result<XpubOrigin<Standard>, XpubRequirementError>, NonStandardDerivation> {
        let standard = Standard::deduce(source);

        if let Some(ref standard) = standard {
            standard
                .extract_account_index(source)
                .transpose()
                .map_err(|err| NonStandardDerivation::UnhardenedAccount(err.0))?;

            if let Some(network) = slip
                .as_ref()
                .and_then(KeyVersion::network::<DefaultResolver>)
            {
                if let Some(standard_network) = standard
                    .network(source)
                    .transpose()
                    .map_err(|err| NonStandardDerivation::UnhardenedCoinType(err.0))?
                {
                    if standard_network != network {
                        return Ok(Err(XpubRequirementError::NetworkMismatch {
                            slip_network: network,
                            bip_network: standard_network,
                        }));
                    }
                }
            }
        }

        Ok(XpubOrigin::with(master_fingerprint, xpub, standard, slip))
    }
}

/// Descriptor for extended public key which may also hold the information
/// information about the key origin.
#[derive(Getters, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct XpubDescriptor<Standard>
where
    Standard: DerivationStandard,
{
    #[getter(as_copy)]
    testnet: bool,
    #[getter(as_copy)]
    depth: u8,
    #[getter(as_copy)]
    parent_fingerprint: Fingerprint,
    #[getter(as_copy)]
    child_number: ChildNumber,
    #[getter(as_copy)]
    public_key: secp256k1::PublicKey,
    #[getter(as_copy)]
    chain_code: ChainCode,

    #[getter(as_copy, as_mut)]
    master_fingerprint: Option<Fingerprint>,
    #[getter(as_ref)]
    standard: Option<Standard>,
    #[getter(as_copy, as_mut)]
    account: Option<HardenedIndex>,
}

/// Error parsing [`XpubDescriptor`] string representation
#[derive(
    Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error, From
)]
#[display(inner)]
pub enum XpubParseError {
    /// BIP32-related error
    #[from]
    Bip32(bip32::Error),

    /// SLIP132-related error
    #[from]
    Slip132(slip132::Error),

    /// Inconsistency error
    #[from]
    Inconsistency(XpubRequirementError),
}

impl<Standard> FromStr for XpubDescriptor<Standard>
where
    Standard: DerivationStandard + Display,
{
    type Err = XpubParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // The string here could be just a xpub, slip132 xpub or xpub prefixed
        // with origin information in a different formats.

        // TODO: Implement `[fp/derivation/path]xpub` processing
        // TODO: Implement `m=[fp]/derivation/path/account=[xpub]` processing

        let xpub = ExtendedPubKey::from_str(s).or_else(|_| ExtendedPubKey::from_slip132_str(s))?;

        let slip = KeyVersion::from_xkey_str(s).ok();

        Ok(XpubDescriptor::with_unchecked(None, xpub, None, slip))
    }
}

impl<Standard> From<ExtendedPubKey> for XpubDescriptor<Standard>
where
    Standard: DerivationStandard,
{
    fn from(xpub: ExtendedPubKey) -> Self {
        XpubDescriptor {
            testnet: xpub.network != bitcoin::Network::Bitcoin,
            depth: xpub.depth,
            parent_fingerprint: xpub.parent_fingerprint,
            child_number: xpub.child_number,
            public_key: xpub.public_key,
            chain_code: xpub.chain_code,
            master_fingerprint: None,
            standard: None,
            account: None,
        }
    }
}

impl<Standard> From<&XpubDescriptor<Standard>> for ExtendedPubKey
where
    Standard: DerivationStandard,
{
    fn from(xpub: &XpubDescriptor<Standard>) -> Self {
        ExtendedPubKey {
            network: if xpub.testnet {
                bitcoin::Network::Testnet
            } else {
                bitcoin::Network::Bitcoin
            },
            depth: xpub.depth,
            parent_fingerprint: xpub.parent_fingerprint,
            child_number: xpub.child_number,
            public_key: xpub.public_key,
            chain_code: xpub.chain_code,
        }
    }
}

impl<Standard> From<XpubDescriptor<Standard>> for ExtendedPubKey
where
    Standard: DerivationStandard,
{
    fn from(xpub: XpubDescriptor<Standard>) -> Self { ExtendedPubKey::from(&xpub) }
}

impl<Standard> XpubDescriptor<Standard>
where
    Standard: DerivationStandard + ToString,
{
    /// Constructs origin information for _an account_-level xpub or deeper key,
    /// parsing it from a given xpub descriptor string.
    /// Ensures consistency of this information and returns error indicating
    /// discovered inconsistency.
    ///
    /// Compares the following correspondences between xpub and SLIP132-encoded
    /// key version:
    /// - network (testnet/mainnet only, since SLIP132 does not cover more
    ///   networks for bitcoin);
    /// - specific BIP43-based derivation standard matching the possible use of
    ///   the extended public key as an account-level key or deeper; basing on
    ///   its depth and child number;
    /// - if the xpub depth matches account key depth defined by the provided
    ///   derivation standard information, the child number of the xpub must be
    ///   a hardened number.
    ///
    /// Also checks that if there is a provided SLIP132 key version and
    /// derivation standard, they do match.
    pub fn from_str_checked(
        s: &str,
        testnet: bool,
        standard: Option<Standard>,
    ) -> Result<XpubDescriptor<Standard>, XpubParseError>
    where
        Standard: Display,
    {
        let mut xd = XpubDescriptor::from_str(s)?;
        let slip = KeyVersion::from_xkey_str(s).ok();
        xd.checked(testnet, slip)?;

        match (&standard, &xd.standard, slip) {
            (Some(required), Some(actual), Some(_)) if required != actual => {
                return Err(XpubParseError::Inconsistency(
                    XpubRequirementError::StandardMismatch {
                        actual_standard: actual.to_string(),
                        required_standard: required.to_string(),
                    },
                ))
            }
            _ => {}
        }
        xd.standard = standard.or(xd.standard);

        Ok(xd)
    }

    /// Constructs origin information for _an account_-level xpub or deeper key,
    /// extracting it from both `xpub` and SLIP132 key version (prefix) data.
    /// Ensures consistency of this information and returns error indicating
    /// discovered inconsistency.
    ///
    /// Compares the following correspondences between xpub and SLIP132-encoded
    /// key version:
    /// - network (testnet/mainnet only, since SLIP132 does not cover more
    ///   networks for bitcoin);
    /// - specific BIP43-based derivation standard matching the possible use of
    ///   the extended public key as an account-level key or deeper; basing on
    ///   its depth and child number;
    /// - if the xpub depth matches account key depth defined by the provided
    ///   derivation standard information, the child number of the xpub must be
    ///   a hardened number.
    ///
    /// Also checks that if there is a provided SLIP132 key version and
    /// derivation standard, they do match.
    pub fn with(
        master_fingerprint: Option<Fingerprint>,
        xpub: ExtendedPubKey,
        testnet: bool,
        standard: Option<Standard>,
        slip: Option<KeyVersion>,
    ) -> Result<XpubDescriptor<Standard>, XpubRequirementError> {
        let mut xd = XpubDescriptor::from(xpub);
        xd.standard = standard;
        xd.master_fingerprint = master_fingerprint;
        xd.checked(testnet, slip)?;
        Ok(xd)
    }

    #[doc(hidden)]
    pub fn with_unchecked(
        master_fingerprint: Option<Fingerprint>,
        xpub: ExtendedPubKey,
        standard: Option<Standard>,
        slip: Option<KeyVersion>,
    ) -> XpubDescriptor<Standard> {
        let mut xd = XpubDescriptor::from(xpub);
        xd.standard = standard.clone();
        xd.master_fingerprint = master_fingerprint;
        let origin = XpubOrigin::with_unchecked(master_fingerprint, xpub, standard, slip);
        xd.account = origin.account;
        xd
    }

    /// Checks the correctness of the key against standards and updates unknown
    /// information from the one which can be guessed from the standard.
    ///
    /// Compares the following correspondences between the self and
    /// SLIP132-encoded key version.
    /// - network (testnet/mainnet only, since SLIP132 does not cover more
    ///   networks for bitcoin);
    /// - specific BIP43-based derivation standard matching the possible use of
    ///   the extended public key as an account-level key or deeper; basing on
    ///   its depth and child number;
    /// - if the xpub depth matches account key depth defined by the provided
    ///   derivation standard information, the child number of the xpub must be
    ///   a hardened number.
    ///
    /// Also checks that if there is a provided SLIP132 key version and
    /// derivation standard, they do match.
    pub fn checked(
        &mut self,
        testnet: bool,
        slip: Option<KeyVersion>,
    ) -> Result<(), XpubRequirementError> {
        if testnet != self.testnet {
            return Err(XpubRequirementError::TestnetMismatch {
                expected: testnet,
                actual: self.testnet,
            });
        }

        let origin = XpubOrigin::with(
            self.master_fingerprint,
            self.clone().into(),
            self.standard.clone(),
            slip,
        )?;
        self.standard = origin.standard;
        self.account = origin.account;
        Ok(())
    }

    /// Deduces key origin information, using derivation path, internal key
    /// metadata and optional SLIP132 version prefix.
    ///
    /// # Returns
    ///
    /// The function ensures that the derivation path matches the standard which
    /// is defined by SLIP132, if the slip information is provided, and errors
    /// with [`NonStandardDerivation`] otherwise. This "extenral" error returned
    /// by the function may indicate the internal inconsistency in the program
    /// logic and can be `expect`'ed in this case.
    ///
    /// The function also checks the key and SLIP132 data for the internal
    /// consistency using [`XpubOrigin::with`] method, and returns
    /// `Ok(`[`XpubRequirementError`]`)` if this check fails. It also checks
    /// that the provided derivation path coin type index matches the network
    /// specified by the SLIP132 and xpub data, also returning
    /// `Ok(`[`XpubRequirementError`]`)` if this check fails. These errors
    /// should not be ignored.
    pub fn deduce(
        master_fingerprint: Option<Fingerprint>,
        source: &DerivationPath,
        xpub: ExtendedPubKey,
        slip: Option<KeyVersion>,
    ) -> Result<Result<XpubDescriptor<Standard>, XpubRequirementError>, NonStandardDerivation> {
        let mut xd = XpubDescriptor::from(xpub);
        let origin = match XpubOrigin::deduce(master_fingerprint, source, xpub, slip) {
            Err(err) => return Err(err),
            Ok(Err(err)) => return Ok(Err(err)),
            Ok(Ok(origin)) => origin,
        };
        xd.standard = origin.standard;
        xd.master_fingerprint = master_fingerprint;
        xd.account = origin.account;
        Ok(Ok(xd))
    }
}

impl<Standard> XpubDescriptor<Standard>
where
    Standard: DerivationStandard,
{
    /// Computes identifier of the extended public key
    pub fn identifier(&self) -> XpubIdentifier {
        let mut engine = XpubIdentifier::engine();
        engine
            .write_all(&self.public_key.serialize())
            .expect("engines don't error");
        XpubIdentifier::from_engine(engine)
    }

    /// Computes fingerprint of the extended public key
    pub fn fingerprint(&self) -> Fingerprint { Fingerprint::from(&self.identifier()[0..4]) }

    /// Converts to [`XpubOrigin`]
    pub fn to_origin(&self) -> XpubOrigin<Standard> {
        XpubOrigin {
            testnet: self.testnet,
            master_fingerprint: self.master_fingerprint,
            standard: self.standard.clone(),
            account: self.account,
        }
    }

    /// Converts into [`XpubOrigin`]
    pub fn into_origin(self) -> XpubOrigin<Standard> {
        XpubOrigin {
            testnet: self.testnet,
            master_fingerprint: self.master_fingerprint,
            standard: self.standard,
            account: self.account,
        }
    }
}
