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

use std::collections::{BTreeMap, BTreeSet};
use std::io::{stdin, stdout, BufRead, Write};
use std::num::ParseIntError;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{fs, io};

use amplify::hex::ToHex;
use amplify::IoError;
use bitcoin::consensus::Encodable;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::address;
use bitcoin::util::bip32::{ChildNumber, ExtendedPubKey};
use bitcoin::util::psbt::{PartiallySignedTransaction as Psbt, PsbtParseError};
use bitcoin::{Address, Network};
use bitcoin_hd::DeriveError;
use clap::Parser;
use colored::Colorize;
use electrum_client as electrum;
use electrum_client::ElectrumApi;
use miniscript::Descriptor;
use psbt::construct::{self, Construct};
use slip132::{DefaultResolver, FromSlip132, KeyVersion, VersionResolver};
use strict_encoding::{StrictDecode, StrictEncode};
use wallet::descriptors::InputDescriptor;
use wallet::hd::{DescriptorDerive, SegmentIndexes, TrackingAccount, UnhardenedIndex};
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
    #[clap(short, long, global = true, default_value("pandora.network"))]
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
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Command {
    /// Create new wallet defined with a given output descriptor
    Create {
        /// Wallet output descriptor. Can use Taproot and miniscript.
        descriptor: Descriptor<TrackingAccount>,

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
            required = true,
            long_help = "\
List of input descriptors, specifying public keys used in generating provided 
UTXOs from the account data. Input descriptors are matched to UTXOs in 
automatic manner.

Input descriptor format:

`txid:vout deriv-terminal [fingerprint:tweak] [rbf|height|time] [sighashtype]`

In the simplest forms, input descriptors are just UTXO outpuint and derivation
terminal info used to create public key corresponding to the output descriptor.
Input descriptors may optionally provide information on public key P2C tweak 
which has to be applied in order to produce valid address and signature; 
this tweak can be provided as a hex value following fingerprint of the tweaked 
key account and `:` sign. The sequence number defaults to `0xFFFFFFFF`; custom 
sequence numbers may be specified via sequence number modifiers (see below). 
If the input should use `SIGHASH_TYPE` other than `SIGHASH_ALL` they may be 
specified at the end of input descriptor.

Sequence number representations:
- `rbf(SEQ)`: use replace-by-fee opt-in for this input;
- `after(NO)`: allow the transaction to be mined with sequence lock
  to `NO` blocks;
- `older(NO)`: allow the transaction to be mined if it is older then
  the provided number `NO` of 5-minute intervals.

SIGHASH_TYPE representations:
- `ALL` (default)
- `SINGLE`
- `NONE`
- `ALL|ANYONECANPAY`
- `NONE|ANYONECANPAY`
- `SINGLE|ANYONECANPAY`
"
        )]
        inputs: Vec<InputDescriptor>,

        /// Addresses and amounts, separated by colon. Amounts are always in
        /// satoshis.
        ///
        /// Example:
        /// "bc1qtkr96rhavl4z4ftxa4mewlvmgd8dnp6pe9nuht:1645621")
        #[clap(short, long = "output", required = true)]
        outputs: Vec<AddressAmount>,

        /// Derivation index for change address
        #[clap(short, long, default_value = "0")]
        change_index: UnhardenedIndex,

        /// Destination file to save constructed PSBT
        psbt_file: PathBuf,

        /// Total fee to pay to the miners, in satoshis.
        /// The fee is used in change calculation; the change address is
        /// added automatically.
        fee: u64,
    },

    /// Try to finalize PSBT
    Finalize {
        /// File containing fully-signed PSBT
        psbt_file: PathBuf,

        /// Destination file to save binary transaction. If no file is given
        /// the transaction is print to the screen in hex form.
        #[clap(short = 'o', long = "output")]
        tx_file: Option<PathBuf>,

        /// Publish the transaction to the network; optional argument allows
        /// to specify some custom network (testnet, for instance).
        #[clap(long)]
        publish: Option<Option<Network>>,
    },

    /// Get info about extended public key data
    Info {
        /// Base58-encoded extended public key
        data: String,
    },

    /// Inspect PSBT or transaction file in binary format. If the file is not
    /// provided it will read user input as a Base-58 encoded string.
    Inspect {
        /// File containing binary PSBT or transaction data to inspect
        file: Option<PathBuf>,
    },

    /// Converts binary PSBT file into a Base58 representation printed to STDIN.
    Convert { file: PathBuf },
}

impl Args {
    fn electrum_client(&self, network: Network) -> Result<electrum::Client, electrum::Error> {
        let electrum_url = format!(
            "{}:{}",
            self.electrum_server,
            self.electrum_port
                .unwrap_or_else(|| default_electrum_port(network))
        );
        eprintln!(
            "Connecting to network {} using {}",
            network.to_string().yellow(),
            electrum_url.yellow()
        );
        electrum::Client::new(&electrum_url)
    }

    pub fn exec(&self) -> Result<(), Error> {
        match &self.command {
            Command::Inspect { file } => self.inspect(file.as_ref()),
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
            Command::Construct {
                locktime,
                wallet_file,
                inputs,
                outputs,
                change_index,
                psbt_file,
                fee,
            } => self.construct(
                wallet_file,
                *locktime,
                inputs,
                outputs,
                *change_index,
                *fee,
                psbt_file,
            ),
            Command::Finalize {
                psbt_file,
                tx_file,
                publish,
            } => self.finalize(
                psbt_file,
                tx_file.as_ref(),
                publish
                    .as_ref()
                    .copied()
                    .map(|n| n.unwrap_or(Network::Bitcoin)),
            ),
            Command::Info { data } => self.info(data.as_str()),
            Command::Convert { file } => self.convert(file),
        }
    }

    fn create(descriptor: &Descriptor<TrackingAccount>, path: &Path) -> Result<(), Error> {
        let file = fs::File::create(path)?;
        descriptor.strict_encode(file)?;
        Ok(())
    }

    fn address(path: &Path, count: u16, skip: u16, show_change: bool) -> Result<(), Error> {
        let secp = Secp256k1::new();

        let file = fs::File::open(path)?;
        let descriptor: Descriptor<TrackingAccount> = Descriptor::strict_decode(file)?;

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

    fn check(&self, path: &Path, batch_size: u16, skip: u16) -> Result<(), Error> {
        let secp = Secp256k1::new();

        let file = fs::File::open(path)?;
        let descriptor: Descriptor<TrackingAccount> = Descriptor::strict_decode(file)?;

        let network = descriptor.network()?;
        let client = self.electrum_client(network)?;

        println!(
            "{}\n{}\n",
            "\nWallet descriptor:".bright_white(),
            descriptor
        );

        let mut total = 0u64;
        let mut single_pat = [UnhardenedIndex::zero(); 1];
        let mut double_pat = [UnhardenedIndex::zero(); 2];
        let derive_pattern = match descriptor.derive_pattern_len()? {
            1 => single_pat.as_mut_slice(),
            2 => double_pat.as_mut_slice(),
            _ => return Err(Error::DescriptorDerivePattern),
        };
        for case in 0u8..(derive_pattern.len() as u8) {
            let mut offset = skip;
            let mut last_count = 1usize;
            if derive_pattern.len() > 1 {
                derive_pattern
                    .first_mut()
                    .map(|idx| *idx = UnhardenedIndex::from(case));
            }
            loop {
                eprint!("Batch {}/{}..{}", case, offset, offset + batch_size);

                let scripts = (offset..(offset + batch_size))
                    .into_iter()
                    .map(UnhardenedIndex::from)
                    .map(|index| {
                        derive_pattern
                            .last_mut()
                            .map(|idx| *idx = UnhardenedIndex::from(index));
                        DescriptorDerive::script_pubkey(&descriptor, &secp, &derive_pattern)
                    })
                    .collect::<Result<Vec<_>, DeriveError>>()?;

                let mut addr_total = 0u64;
                let mut count = 0usize;
                eprint!(" ... ");
                for ((index, batch), script) in client
                    .batch_script_list_unspent(&scripts)?
                    .into_iter()
                    .enumerate()
                    .zip(scripts)
                {
                    if batch.is_empty() {
                        continue;
                    }
                    count += batch.len();

                    let derive_term = format!("{}/{}", case, offset as usize + index);
                    if let Some(address) = Address::from_script(&script, network) {
                        println!(
                            "\n  {} address {}:",
                            derive_term.bright_white(),
                            address.to_string().bright_white(),
                        );
                    } else {
                        println!(
                            "\n  {} no-address script {}:",
                            derive_term.bright_white(),
                            script
                        );
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

    fn info(&self, data: &str) -> Result<(), Error> {
        let xpub = ExtendedPubKey::from_slip132_str(data)?;
        println!();
        println!("Fingerprint: {}", xpub.fingerprint());
        println!("Identifier: {}", xpub.identifier());
        println!("Network: {}", xpub.network);
        println!("Public key: {}", xpub.public_key);
        println!("Chain code: {}", xpub.chain_code);
        match KeyVersion::from_xkey_str(data) {
            Ok(ver) => {
                if let Some(application) = DefaultResolver::application(&ver) {
                    println!("Application: {}", application);
                }
                if let Some(derivation_path) = DefaultResolver::derivation_path(&ver, None) {
                    println!("Derivation: {}", derivation_path);
                } else if let Some(derivation_path) =
                    DefaultResolver::derivation_path(&ver, Some(ChildNumber::Hardened { index: 0 }))
                {
                    println!("Derivation: {} (account #0)", derivation_path);
                }
            }
            Err(err) => eprintln!(
                "Application: {} {}",
                "unable to read SLIP-132 information.".bright_red(),
                err
            ),
        }
        println!("Depth: {}", xpub.depth);
        println!("Child number: {:#}", xpub.child_number);
        println!();

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn construct(
        &self,
        wallet_path: &Path,
        lock_time: LockTime,
        inputs: &[InputDescriptor],
        outputs: &[AddressAmount],
        change_index: UnhardenedIndex,
        fee: u64,
        psbt_path: &Path,
    ) -> Result<(), Error> {
        let secp = Secp256k1::new();

        let file = fs::File::open(wallet_path)?;
        let descriptor: Descriptor<TrackingAccount> = Descriptor::strict_decode(file)?;
        let network = descriptor.network()?;
        let electrum_url = format!(
            "{}:{}",
            self.electrum_server,
            self.electrum_port
                .unwrap_or_else(|| default_electrum_port(network))
        );
        let client = electrum::Client::new(&electrum_url)?;

        println!(
            "{}\n{}\n",
            "\nWallet descriptor:".bright_white(),
            descriptor
        );
        eprint!(
            "Re-scanning network {} using {} ... ",
            network.to_string().yellow(),
            electrum_url.yellow()
        );

        let txid_set: BTreeSet<_> = inputs.iter().map(|input| input.outpoint.txid).collect();
        let tx_map = client
            .batch_transaction_get(&txid_set)?
            .into_iter()
            .map(|tx| (tx.txid(), tx))
            .collect::<BTreeMap<_, _>>();

        eprintln!("{}", "done\n".green());

        let outputs = outputs
            .iter()
            .map(|a| (a.address.clone(), a.amount))
            .collect::<Vec<_>>();
        let psbt = Psbt::construct(
            &secp,
            &descriptor,
            lock_time,
            inputs,
            &outputs,
            change_index,
            fee,
            &tx_map,
        )?;

        let file = fs::File::create(psbt_path)?;
        psbt.consensus_encode(file)?;

        println!("{} {}\n", "PSBT:".bright_white(), psbt);

        Ok(())
    }

    fn finalize(
        &self,
        psbt_path: &Path,
        tx_path: Option<&PathBuf>,
        publish: Option<Network>,
    ) -> Result<(), Error> {
        let secp = Secp256k1::new();

        let file = fs::File::open(psbt_path)?;
        let mut psbt = Psbt::strict_decode(&file)?;

        miniscript::psbt::finalize(&mut psbt, &secp)?;

        let tx = psbt.extract_tx();

        if let Some(tx_path) = tx_path {
            let file = fs::File::create(tx_path)?;
            tx.strict_encode(file)?;
        } else {
            println!(
                "{}\n",
                tx.strict_serialize()
                    .expect("memory encoders does not error")
                    .to_hex()
            );
        }

        if let Some(network) = publish {
            let client = self.electrum_client(network)?;
            client.transaction_broadcast(&tx)?;
            eprintln!(
                "{} {} {}\n",
                "Transaction".bright_yellow(),
                tx.txid().to_string().yellow(),
                "published".bright_yellow()
            );
        }

        Ok(())
    }

    fn inspect(&self, path: Option<&PathBuf>) -> Result<(), Error> {
        let psbt = if let Some(path) = path {
            let file = fs::File::open(path)?;
            Psbt::strict_decode(&file)?
        } else {
            eprint!("Type in Base58 encoded PSBT and press enter: ");
            stdout().flush()?;
            let stdin = stdin();
            let psbt58 = stdin.lock().lines().next().expect("no PSBT data")?;
            Psbt::from_str(psbt58.trim())?
        };
        println!("\n{}", serde_yaml::to_string(&psbt)?);
        Ok(())
    }

    fn convert(&self, path: &Path) -> Result<(), Error> {
        let file = fs::File::open(path)?;
        let psbt = Psbt::strict_decode(&file)?;
        println!("\n{}\n", psbt);
        Ok(())
    }
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
    InvalidAmount(ParseIntError),
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
    pub amount: u64,
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

    #[from]
    Yaml(serde_yaml::Error),

    #[from]
    PsbtBase58(PsbtParseError),

    #[from]
    PsbtConstruction(construct::Error),

    #[from]
    PsbtFinalization(miniscript::psbt::Error),

    /// unrecognized number of wildcards in the descriptor derive pattern
    #[display(doc_comments)]
    DescriptorDerivePattern,

    /// error in extended key encoding: {0}
    #[from]
    XkeyEncoding(slip132::Error),
}

fn main() -> Result<(), Error> {
    let args = Args::parse();
    args.exec()
}
