// BP foundation libraries Bitcoin crates implementing the foundations of
// Bitcoin protocol by LNP/BP Association (https://lnp-bp.org)
//
// Written in 2020-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// This software is distributed without any warranty.
//
// You should have received a copy of the Apache-2.0 License
// along with this software.
// If not, see <https://opensource.org/licenses/Apache-2.0>.

//! Bitcoin blockchain data structures.

#[macro_use]
extern crate amplify;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;

pub mod locks;
