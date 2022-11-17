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

use bitcoin::Network;
use bitcoin_hd::standards::DerivationBlockchain;

/// Public variants of bitcoin networks
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub enum PublicNetwork {
    /// Bitcoin mainnet
    #[display("mainnet")]
    Mainnet,

    /// Bitcoin testnet3
    #[display("testnet")]
    Testnet,

    /// Bitcoin signet
    #[display("signet")]
    Signet,
}

impl From<PublicNetwork> for Network {
    fn from(network: PublicNetwork) -> Self {
        Network::from(&network)
    }
}

impl From<&PublicNetwork> for Network {
    fn from(network: &PublicNetwork) -> Self {
        match network {
            PublicNetwork::Mainnet => Network::Bitcoin,
            PublicNetwork::Testnet => Network::Testnet,
            PublicNetwork::Signet => Network::Signet,
        }
    }
}

impl TryFrom<Network> for PublicNetwork {
    type Error = ();
    fn try_from(network: Network) -> Result<Self, Self::Error> {
        Ok(match network {
            Network::Bitcoin => PublicNetwork::Mainnet,
            Network::Testnet => PublicNetwork::Testnet,
            Network::Signet => PublicNetwork::Signet,
            Network::Regtest => return Err(()),
        })
    }
}

impl From<PublicNetwork> for DerivationBlockchain {
    fn from(network: PublicNetwork) -> Self {
        DerivationBlockchain::from(&network)
    }
}

impl From<&PublicNetwork> for DerivationBlockchain {
    fn from(network: &PublicNetwork) -> Self {
        match network {
            PublicNetwork::Mainnet => DerivationBlockchain::Bitcoin,
            PublicNetwork::Testnet => DerivationBlockchain::Testnet,
            PublicNetwork::Signet => DerivationBlockchain::Testnet,
        }
    }
}

impl Default for PublicNetwork {
    fn default() -> Self {
        PublicNetwork::Testnet
    }
}

impl PublicNetwork {
    /// Detects if the public network is belongs to a testnet
    pub fn is_testnet(self) -> bool {
        matches!(self, PublicNetwork::Testnet | PublicNetwork::Signet)
    }

    /// Returns default electrum server port for the network
    pub fn electrum_port(self) -> u16 {
        match self {
            PublicNetwork::Mainnet => 50001,
            PublicNetwork::Testnet => 60001,
            PublicNetwork::Signet => 60601,
        }
    }
}
