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

#[macro_use]
extern crate clap;
#[macro_use]
extern crate amplify;

use std::path::PathBuf;

use wallet::hd::{DerivationScheme, HardenedIndex};

/// Command-line arguments
#[derive(Parser)]
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[clap(author, version, about = "Command-line file-based bitcoin hot wallet")]
pub struct Args {
    /// Command to execute
    #[clap(subcommand)]
    pub command: Command,
}

/// Wallet command to execute
#[derive(Subcommand)]
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum Command {
    /// Generate new seed and saves it as an encoded file
    Seed {
        /// File to save generated seed data and extended master key
        output_file: PathBuf,
    },

    /// Derive new extended private key from the seed and saves it into a
    /// separate file as a new signing account
    Derive {
        /// Seed file containing extended master key, created previously with
        /// `seed` command.
        seed_file: PathBuf,

        #[clap(short, long, default_value = "bip86")]
        scheme: DerivationScheme,

        #[clap(short, long, default_value = "0'")]
        account: HardenedIndex,

        /// Use the seed for bitcoin mainnet
        #[clap(long, group = "network")]
        mainnet: bool,

        /// Use the seed for bitcoin testnet
        #[clap(long, group = "network")]
        testnet: bool,

        /// Use the seed for bitcoin signet
        #[clap(long, group = "network")]
        signet: bool,

        /// Output file for storing account-based extended private key
        output_file: PathBuf,
    },

    /// Print information about seed or the signing account. Private keys are
    /// never print.
    Info {
        /// File containing either seed information or extended private key for
        /// the account, previously created with `seed` and `derive`
        /// commands.
        file: PathBuf,
    },

    /// Sign PSBT with the provided account keys
    Sign {
        /// File containing PSBT
        psbt_file: PathBuf,

        /// Signing account file used to (partially co-)sign PSBT
        signing_account: PathBuf,
    },
}

#[derive(
    Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error, From
)]
#[display(doc_comments)]
pub enum Error {}

fn main() -> Result<(), Error> { Ok(()) }
