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
use std::str::FromStr;
use std::{fs, io};

use amplify::IoError;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::address;
use bitcoin::util::amount::ParseAmountError;
use bitcoin::{Address, Amount, Network, OutPoint};
use bitcoin_hd::DeriveError;
use clap::Parser;
use colored::Colorize;
use electrum_client as electrum;
use electrum_client::ElectrumApi;
use miniscript::Descriptor;
use strict_encoding::{StrictDecode, StrictEncode};
use wallet::descriptors::InputDescriptor;
use wallet::hd::{ChildIndex, DescriptorDerive, PubkeyChain, UnhardenedIndex};
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
        short,
        long,
        global = true,
        default_value("electrum.blockstream.info")
    )]
    pub electrum_server: String,

    /// Customize electrum server port number. By default the wallet will use
    /// port matching the selected network.
    #[clap(short = 'p', global = true)]
    pub electrum_port: Option<u16>,
    /*
    /// Bitcoin Core backend to use. If used, overrides `electrum_server`,
    /// which becomes unused.
    ///
    /// Used only by `check`, `history`, `construct` and some forms of
    /// `extract` command
    #[clap(long, global = true, conflicts_with = "electrum-server")]
    pub bitcoin_core: Option<String>,
     */
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

        /// Minimum number of addresses to look ahead
        #[clap(short = 'n', long, default_value = "20")]
        look_ahead: u16,

        /// Number of addresses to skip
        #[clap(short, long, default_value = "0")]
        skip: u16,
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

        /// Number of addresses to skip
        #[clap(short, long, default_value = "0")]
        skip: u16,

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

impl Args {
    pub fn exec(&self) -> Result<(), Error> {
        match &self.command {
            Command::Inspect { file } => Self::inspect(file),
            Command::Create {
                descriptor,
                output_file,
            } => Self::create(descriptor, output_file),
            Command::Check {
                wallet_file,
                look_ahead,
                skip,
            } => self.check(wallet_file, *look_ahead, *skip),
            Command::History { .. } => self.history(),
            Command::Address {
                wallet_file,
                count,
                skip,
                show_change,
            } => Self::address(wallet_file, *count, *skip, *show_change),
            Command::Construct { .. } => Self::construct(),
            Command::Finalize { .. } => Self::finalize(),
            Command::Extract { .. } => Self::extract(),
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
        skip: u16,
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

        if descriptor.derive_pattern_len()? != 2 {
            return Err(Error::DescriptorDerivePattern);
        }
        for index in skip..(skip + count) {
            let address = DescriptorDerive::address(&descriptor, &secp, &[
                UnhardenedIndex::from(if show_change { 1u8 } else { 0u8 }),
                UnhardenedIndex::from(index),
            ])?;

            println!("{:>6} {}", format!("#{}", index).dimmed(), address);
        }

        println!();

        Ok(())
    }

    fn check(
        &self,
        path: &PathBuf,
        batch_size: u16,
        skip: u16,
    ) -> Result<(), Error> {
        let secp = Secp256k1::new();

        let file = fs::File::open(path)?;
        let descriptor: Descriptor<PubkeyChain> =
            Descriptor::strict_decode(file)?;

        let network = descriptor.network()?;
        let electrum_url = format!(
            "{}:{}",
            self.electrum_server,
            self.electrum_port.unwrap_or(default_electrum_port(network))
        );
        let client = electrum::Client::new(&electrum_url)?;

        println!(
            "{}\n{}\n",
            "\nWallet descriptor:".bright_white(),
            descriptor
        );
        eprintln!(
            "Scanning network {} using {}",
            network.to_string().yellow(),
            electrum_url.yellow()
        );

        let mut total = 0u64;
        if descriptor.derive_pattern_len()? != 2 {
            return Err(Error::DescriptorDerivePattern);
        }
        for case in 0u8..=1 {
            let mut offset = skip;
            let mut last_count = 1usize;
            loop {
                eprint!("Batch {}/{}..{}", case, offset, offset + batch_size);

                let scripts = (offset..(offset + batch_size))
                    .into_iter()
                    .map(UnhardenedIndex::from)
                    .map(|index| {
                        DescriptorDerive::script_pubkey(&descriptor, &secp, &[
                            UnhardenedIndex::from(case),
                            UnhardenedIndex::from(index),
                        ])
                    })
                    .collect::<Result<Vec<_>, DeriveError>>()?;

                let mut addr_total = 0u64;
                let mut count = 0usize;
                eprint!(" ... ");
                for (batch, script) in client
                    .batch_script_list_unspent(&scripts)?
                    .into_iter()
                    .zip(scripts)
                {
                    if batch.is_empty() {
                        continue;
                    }
                    count += batch.len();

                    if let Some(address) =
                        Address::from_script(&script, network)
                    {
                        println!("\nAddress {}:", address);
                    } else {
                        println!("\nNo-address script {}:", script);
                    }

                    for res in batch {
                        println!(
                            "{:>10} @ {}:{} - {} block",
                            res.value.to_string().bright_yellow(),
                            res.tx_hash,
                            res.tx_pos,
                            res.height
                        );
                        addr_total += res.value;
                    }
                }

                offset += batch_size;
                total += addr_total;

                if count == 0 {
                    eprintln!("empty");
                }
                if last_count == 0 && count == 0 {
                    break;
                }
                last_count = count;
            }
        }

        println!(
            "Total {} sats\n",
            total.to_string().bright_yellow().underline()
        );

        Ok(())
    }

    fn history(&self) -> Result<(), Error> { todo!() }
    fn construct() -> Result<(), Error> { todo!() }
    fn finalize() -> Result<(), Error> { todo!() }
    fn extract() -> Result<(), Error> { todo!() }
    fn inspect(file: &PathBuf) -> Result<(), Error> { todo!() }
}

fn default_electrum_port(network: Network) -> u16 {
    match network {
        Network::Bitcoin => 50001,
        Network::Testnet => 60001,
        Network::Signet | Network::Regtest => 60601,
    }
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

    #[from]
    Derive(DeriveError),

    #[from]
    Electrum(electrum::Error),

    /// unrecognized number of wildcards in the descriptor derive pattern
    #[display(doc_comments)]
    DescriptorDerivePattern,
}

fn main() -> Result<(), Error> {
    let args = Args::parse();
    args.exec()
}
