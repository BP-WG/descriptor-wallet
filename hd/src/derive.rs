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

/// the provided derive pattern does not match descriptor derivation
/// wildcard
#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error
)]
#[display(doc_comments)]
pub struct DerivePatternError;

/// Errors during descriptor derivation
#[derive(Debug, Display, From)]
#[display(doc_comments)]
pub enum DeriveError {
    /// account-level extended public in the descriptor has different network
    /// requirements
    InconsistentKeyNetwork,

    /// key derivation in the descriptor uses inconsistent wildcard pattern
    InconsistentKeyDerivePattern,

    /// the provided derive pattern does not match descriptor derivation
    /// wildcard
    #[from(DerivePatternError)]
    DerivePatternMismatch,

    /// descriptor contains no keys; corresponding outputs will be
    /// "anyone-can-sped"
    NoKeys,

    /// descriptor does not support address generation
    NoAddressForDescriptor,

    /// unable to derive script public key for the descriptor; possible
    /// incorrect miniscript for the descriptor context
    DescriptorFailure,

    /// miniscript-specific failure
    #[from]
    Miniscript(miniscript::Error),
}

impl std::error::Error for DeriveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DeriveError::InconsistentKeyNetwork => None,
            DeriveError::InconsistentKeyDerivePattern => None,
            DeriveError::DerivePatternMismatch => None,
            DeriveError::NoKeys => None,
            DeriveError::NoAddressForDescriptor => None,
            DeriveError::DescriptorFailure => None,
            DeriveError::Miniscript(err) => Some(err),
        }
    }
}
