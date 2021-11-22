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

use std::cell::Cell;
use std::path::PathBuf;
use std::str::FromStr;
use std::{fs, io};

use amplify::IoError;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::address;
use bitcoin::util::amount::ParseAmountError;
use bitcoin::{Address, Amount, OutPoint};
use bitcoin_hd::UnhardenedIndex;
use clap::Parser;
use colored::Colorize;
use miniscript::{Descriptor, DescriptorTrait, TranslatePk2};
use strict_encoding::{StrictDecode, StrictEncode};
use wallet::descriptors::InputDescriptor;
use wallet::hd::{PubkeyChain, TerminalStep};
use wallet::locks::LockTime;

/// Command-line arguments
#[derive(Parser)]
#[derive(Clone, Eq, PartialEq, Debug)]
#[clap(
    author,
    version,
    name = "btc-cold",
    about = "Command-line file-based bitcoin descriptor read-only wallet"
)]
pub struct Args {
    /// Command to execute
    #[clap(subcommand)]
    pub command: Command,

    /// Electrum server to use.
    ///
    /// Used only by `check`, `history`, `construct` and some forms of
    /// `extract` command
    #[clap(
        long,
        global = true,
        default_value_if("bitcoin-core", None, Some("pandora.network"))
    )]
    pub electrum_server: Option<String>,

    /// Bitcoin Core backend to use. If used, overrides `electrum_server`,
    /// which becomes unused.
    ///
    /// Used only by `check`, `history`, `construct` and some forms of
    /// `extract` command
    #[clap(long, global = true, conflicts_with = "electrum-server")]
    pub bitcoin_core: Option<String>,
}

/// Wallet command to execute
#[derive(Subcommand)]
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Command {
    /// Create new wallet defined with a given output descriptor
    Create {
        /// Wallet output descriptor. Can use Taproot and miniscript.
        descriptor: Descriptor<PubkeyChain>,

        /// File to save descriptor info
        output_file: PathBuf,
    },

    /// Read UTXO set from a provided Electrum server for a given descriptor
    /// wallet file
    Check {
        /// Path to the read-only wallet file generated with `create` command
        wallet_file: PathBuf,
    },

    /// Read history of operations with descriptor controlled outputs from
    /// bitcoin blockchain for a given wallet file
    History {
        /// Path to the read-only wallet file generated with `create` command
        wallet_file: PathBuf,
    },

    /// List addresses corresponding to the given descriptor wallet
    Address {
        /// Path to the read-only wallet file generated with `create` command
        wallet_file: PathBuf,

        /// Number of addresses to list
        #[clap(short = 'n', long, default_value = "20")]
        count: u16,

        /// Whether or not to show addresses which are already used
        #[clap(short = 'u', long = "used")]
        show_used: bool,

        /// Whether or not to show change addresses
        #[clap(short = 'c', long = "change")]
        show_change: bool,
    },

    /// Construct new PSBT.
    ///
    /// Checks that given UTXOs belong to the specified wallet descriptor.
    ///
    /// Automatically adds change address generated according to the
    /// descriptor rules.
    ///
    /// Command limitations: UTXO must all be recognizable by the provided
    /// wallet output descriptor and belong to the same wallet.
    Construct {
        /// `nLockTime` for the transaction
        #[clap(short, long, default_value = "none")]
        locktime: LockTime,

        /// Path to the read-only wallet file generated with `create` command
        wallet_file: PathBuf,

        /// List of input descriptors, specifying public keys used in
        /// generating provided UTXOs from the account data.

        #[clap(
            short,
            long = "input",
            min_values = 1,
            long_about = "\
List of input descriptors, specifying public keys used in
generating provided UTXOs from the account data.
Input descriptors are matched to UTXOs in automatic manner.

Input descriptor format:
'['<account-fingerprint>']/'<derivation>['+'<tweak>]['@'<segno>]['#'\
                          <sighashtype>]

In the simplest forms, input descriptors are just derivation index
used to create public key corresponding to the output descriptor.
If a change purpose is used in the derivation, the index must
start with `^` sign. Input descriptors may optionally provide
information on public key P2C tweak which has to be applied in
order to produce valid address and signature; this tweak
can be provided as a hex value following `+` sign. The sequence
number defaults to `0xFFFFFFFF`; custom sequence numbers may be
specified after `@` prefix. If the input should use
`SIGHASH_TYPE` other than `SIGHASH_ALL` it may be specified
at the end of input descriptor after `#` symbol.

Sequence number representations:
- `rbf`: use replace-by-fee opt-in for this input;
- `after:NO`: allow the transaction to be mined with sequence lock
  to `NO` blocks;
- `older:NO`: allow the transaction to be mined if it is older then
  the provided number `NO` of 5-minute intervals.

SIGHASH_TYPE representations:
- `ALL` (default)
- `SINGLE`
- `NONE`
- `ALL|ANYONECANPAY`
- `NONE|ANYONECANPAY`
- `SINGLE|ANYONECANPAY`

Examples:
- simple key: 
  `[89c8f39a]/15/0`
- custom sighash: 
  `[89c8f39a]/15/0#NONE|ANYONECANPAY`
- RBF: 
  `[89c8f39a]/15/0@rbf`
- relative timelock: 
  `[89c8f39a]/15/0@after:10`
- tweaked key: 
  `[89c8f39a]/15/0+596fbbdb1716ab273a7cfa942c66836706ff97a7`
- all together:
  `[89c8f39a]/15/0+596fbbdb1716ab273a7cfa942c66836706ff97a7@after:10#SINGLE`
"
        )]
        input_descriptors: Vec<InputDescriptor>,

        /// Addresses and amounts either in form of `btc` or `sat`, joined via
        /// `:`
        #[clap(short, long, min_values = 1)]
        to: Vec<AddressAmount>,

        /// Destination file to save constructed PSBT
        psbt_file: PathBuf,

        /// Total fee to pay to the miners, either in `btc` or `sat`.
        /// The fee is used in change calculation.
        fee: Amount,

        /// List of UTXOs to spend.
        /// Each UTXO have a form of bitcoin outpoint (`txid:vout`).
        #[clap(min_values = 1)]
        utxos: Vec<OutPoint>,
    },

    /// Try to finalize PSBT
    Finalize {
        /// File containing fully-signed PSBT
        psbt_input_file: PathBuf,

        /// Output file for finalized PSBT
        psbt_output_file: PathBuf,
    },

    /// Extract signed transaction from finalized PSBT and optionally
    /// publishes it to Bitcoin network through Bitcoin Core node or
    /// Electrum server
    Extract {
        /// File containing PSBT, previously finalized with `finalize` command
        psbt_file: PathBuf,

        /// Destination file to save binary transaction. If no file is given
        /// the transaction is print to the screen in hex form.
        #[clap(short = 'o', long = "output")]
        tx_output_file: Option<PathBuf>,

        /// Publish the transaction to the bitcoin network via Electrum Server
        /// or Bitcoin Core node.
        #[clap(short, long)]
        publish: bool,
    },

    /// Inspect PSBT or transaction file
    Inspect {
        /// File containing binary PSBT or transaction data to inspect
        file: PathBuf,
    },
}

impl Command {
    pub fn exec(&self) -> Result<(), Error> {
        match self {
            Command::Inspect { file } => Command::inspect(file),
            Command::Create {
                descriptor,
                output_file,
            } => Command::create(descriptor, output_file),
            Command::Check { .. } => Command::check(),
            Command::History { .. } => Command::history(),
            Command::Address {
                wallet_file,
                count,
                show_used,
                show_change,
            } => {
                Command::address(wallet_file, *count, *show_used, *show_change)
            }
            Command::Construct { .. } => Command::construct(),
            Command::Finalize { .. } => Command::finalize(),
            Command::Extract { .. } => Command::extract(),
        }
    }

    fn create(
        descriptor: &Descriptor<PubkeyChain>,
        path: &PathBuf,
    ) -> Result<(), Error> {
        let file = fs::File::create(path)?;
        descriptor.strict_encode(file)?;
        Ok(())
    }

    fn address(
        path: &PathBuf,
        count: u16,
        show_used: bool,
        show_change: bool,
    ) -> Result<(), Error> {
        let secp = Secp256k1::new();

        let file = fs::File::open(path)?;
        let descriptor: Descriptor<PubkeyChain> =
            Descriptor::strict_decode(file)?;

        println!(
            "{}\n{}\n",
            "\nWallet descriptor:".bright_white(),
            descriptor
        );

        let network = Cell::new(None);
        let warning = Cell::new(false);
        for index in 0..count {
            let d = descriptor.translate_pk2_infallible(|chain| {
                // TODO: Add convenience PubkeyChain methods
                match (network.get(), chain.branch_xpub.network) {
                    (None, _) => network.set(Some(chain.branch_xpub.network)),
                    (Some(n1), n2) if n1 != n2 && !warning.get() => {
                        eprintln!(
                            "{} public keys in descriptor belong to different \
                             network types; will derive testnet addresses \
                             only as a precaution",
                            "Warning:".yellow()
                        );
                        network.set(Some(bitcoin::Network::Testnet));
                        warning.set(true);
                    }
                    _ => {}
                };
                let mut path = chain.terminal_path.clone();
                if path.last() == Some(&TerminalStep::Wildcard) {
                    path.remove(path.len() - 1);
                }
                let index = UnhardenedIndex::from(index);
                path.push(TerminalStep::Index(index.into()));
                let mut chain = chain.clone();
                chain.terminal_path = path;
                chain.derive_pubkey(&secp, None)
            });
            if network.get().is_none() {
                eprintln!(
                    "{} wallet descriptor does not contain any public key \
                     requirement and potentially can be spent by anybody; \
                     switching to testnet address to avoid fund loss",
                    "Warning".yellow()
                );
            }
            let address =
                d.address(network.get().unwrap_or(bitcoin::Network::Testnet))?;
            println!("{:>6} {}", format!("#{}", index).dimmed(), address);
        }

        println!();

        Ok(())
    }

    fn check() -> Result<(), Error> { todo!() }
    fn history() -> Result<(), Error> { todo!() }
    fn construct() -> Result<(), Error> { todo!() }
    fn finalize() -> Result<(), Error> { todo!() }
    fn extract() -> Result<(), Error> { todo!() }
    fn inspect(file: &PathBuf) -> Result<(), Error> { Ok(()) }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
#[display(doc_comments)]
pub enum ParseError {
    /// invalid format for output amount; it must be `address:amount` string
    InvalidFormat,

    /// invalid address
    #[from]
    InvalidAddress(address::Error),

    /// invalid amount
    #[from]
    InvalidAmount(ParseAmountError),
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseError::InvalidFormat => None,
            ParseError::InvalidAddress(err) => Some(err),
            ParseError::InvalidAmount(err) => Some(err),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display("{address}:{amount}", alt = "{address:#}:{amount:#}")]
pub struct AddressAmount {
    pub address: Address,
    pub amount: Amount,
}

impl FromStr for AddressAmount {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split(':');
        match (split.next(), split.next(), split.next()) {
            (Some(addr), Some(val), None) => Ok(AddressAmount {
                address: addr.parse()?,
                amount: val.parse()?,
            }),
            _ => Err(ParseError::InvalidFormat),
        }
    }
}

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum Error {
    #[from(io::Error)]
    Io(IoError),

    #[from]
    StrictEncoding(strict_encoding::Error),

    #[from]
    Miniscript(miniscript::Error),
}

fn main() -> Result<(), Error> {
    let args = Args::parse();
    args.command.exec()
}
