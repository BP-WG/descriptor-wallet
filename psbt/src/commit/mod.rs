// Descriptor wallet library extending bitcoin & miniscript functionality
// by LNP/BP Association (https://lnp-bp.org)
// Written in 2020-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the Apache-2.0 License
// along with this software.
// If not, see <https://opensource.org/licenses/Apache-2.0>.

//! Managing commitment-related proprietary keys inside PSBT.
//!
//! Supports [`tapret`], [`p2c`] and [`s2c`] commitments and LNPBP4 structures
//! used by all of them.

mod lnpbp4;
mod p2c;
mod tapret;

pub use lnpbp4::{
    Lnpbp4Info, Lnpbp4KeyError, ProprietaryKeyLnpbp4, PSBT_GLOBAL_LNPBP4_PROTOCOL_INFO,
    PSBT_LNPBP4_PREFIX, PSBT_OUT_LNPBP4_ENTROPY, PSBT_OUT_LNPBP4_MESSAGE,
    PSBT_OUT_LNPBP4_MIN_TREE_DEPTH,
};
pub use p2c::{PSBT_IN_P2C_TWEAK, PSBT_P2C_PREFIX};
pub use tapret::{
    DfsPathEncodeError, ProprietaryKeyTapret, TapretKeyError, PSBT_IN_TAPRET_TWEAK,
    PSBT_OUT_TAPRET_COMMITMENT, PSBT_OUT_TAPRET_HOST, PSBT_OUT_TAPRET_PROOF, PSBT_TAPRET_PREFIX,
};
