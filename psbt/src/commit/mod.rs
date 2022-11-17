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

// TODO: Relocate to BP DBC library

//! Managing commitment-related proprietary keys inside PSBT.
//!
//! Supports Tapret, Opret, P2C and S2C commitments and LNPBP4 structures used
//! by all of them.

mod lnpbp4;
mod opret;
mod p2c;
mod tapret;

pub use lnpbp4::{
    Lnpbp4Info, Lnpbp4KeyError, ProprietaryKeyLnpbp4, PSBT_GLOBAL_LNPBP4_PROTOCOL_INFO,
    PSBT_LNPBP4_PREFIX, PSBT_OUT_LNPBP4_ENTROPY, PSBT_OUT_LNPBP4_MESSAGE,
    PSBT_OUT_LNPBP4_MIN_TREE_DEPTH,
};
pub use opret::{
    OpretKeyError, ProprietaryKeyOpret, PSBT_OPRET_PREFIX, PSBT_OUT_OPRET_COMMITMENT,
    PSBT_OUT_OPRET_HOST,
};
pub use p2c::{PSBT_IN_P2C_TWEAK, PSBT_P2C_PREFIX};
pub use tapret::{
    DfsPathEncodeError, ProprietaryKeyTapret, TapretKeyError, PSBT_IN_TAPRET_TWEAK,
    PSBT_OUT_TAPRET_COMMITMENT, PSBT_OUT_TAPRET_HOST, PSBT_OUT_TAPRET_PROOF, PSBT_TAPRET_PREFIX,
};
