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
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{fs, io};

use amplify::hex::ToHex;
use amplify::IoError;
use bitcoin::consensus::Encodable;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::address;
use bitcoin::util::amount::ParseAmountError;
use bitcoin::util::taproot::{LeafVersion, TapLeafHash};
use bitcoin::{Address, Amount, Network, Script, Transaction, TxIn, TxOut, Txid};
use bitcoin_hd::DeriveError;
use clap::Parser;
use colored::Colorize;
use electrum_client as electrum;
use electrum_client::ElectrumApi;
use miniscript::{Descriptor, DescriptorTrait, ForEachKey, ToPublicKey};
use psbt::{Input, Output, Psbt};
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
    #[clap(short, long, global = true, default_value("electrum.blockstream.info"))]
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
            long_about = "\
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

        /// Addresses and amounts, either in form of `btc` or `sat`).
        ///
        /// Example:
        /// "bc1qtkr96rhavl4z4ftxa4mewlvmgd8dnp6pe9nuht 0.16btc")
        #[clap(short, long = "output")]
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

    /// Inspect PSBT or transaction file
    Inspect {
        /// File containing binary PSBT or transaction data to inspect
        file: PathBuf,
    },
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
                            index,
                        ])
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
        eprintln!(
            "Scanning network {} using {}",
            network.to_string().yellow(),
            electrum_url.yellow()
        );

        let mut outputs = outputs.to_vec();
        let txid_set: BTreeSet<_> = inputs.iter().map(|input| input.outpoint.txid).collect();
        let tx_set = client
            .batch_transaction_get(&txid_set)?
            .into_iter()
            .map(|tx| (tx.txid(), tx))
            .collect::<BTreeMap<_, _>>();

        let mut xpub = bmap! {};
        descriptor.for_each_key(|key| {
            let account = key.as_key();
            if let Some(key_source) = account.account_key_source() {
                xpub.insert(account.account_xpub, key_source);
            }
            true
        });

        let mut total_spent = 0u64;
        let psbt_inputs = inputs
            .iter()
            .map(|input| {
                let txid = input.outpoint.txid;
                let tx = tx_set.get(&txid).ok_or(Error::TransactionUnknown(txid))?;
                let output = tx
                    .output
                    .get(input.outpoint.vout as usize)
                    .ok_or(Error::OutputUnknown(txid, input.outpoint.vout))?;
                let output_descriptor = descriptor.derive_descriptor(&secp, &input.terminal)?;
                let script_pubkey = output_descriptor.script_pubkey()?;
                if output.script_pubkey != script_pubkey {
                    return Err(Error::ScriptPubkeyMismatch(
                        txid,
                        input.outpoint.vout,
                        output.script_pubkey.clone(),
                        script_pubkey,
                    ));
                }
                let lock_script = output_descriptor.explicit_script()?;
                let mut bip32_derivation = bmap! {};
                let result = descriptor.for_each_key(|key| {
                    let account = key.as_key();
                    match account.bip32_derivation(&secp, &input.terminal) {
                        Ok((pubkey, key_source)) => {
                            bip32_derivation.insert(pubkey, key_source);
                            true
                        }
                        Err(_) => false,
                    }
                });
                if !result {
                    return Err(DeriveError::DerivePatternMismatch.into());
                }

                total_spent += output.value;

                let dtype = descriptors::FullType::from(&output_descriptor);
                let mut psbt_input = Input {
                    bip32_derivation,
                    sighash_type: Some(input.sighash_type),
                    ..Default::default()
                };
                if dtype.is_segwit() {
                    psbt_input.witness_utxo = Some(output.clone());
                } else {
                    psbt_input.non_witness_utxo = Some(tx.clone());
                }
                if let Descriptor::Tr(mut tr) = output_descriptor {
                    psbt_input.bip32_derivation.clear();
                    psbt_input.tap_internal_key = Some(tr.internal_key().to_x_only_pubkey());
                    psbt_input.tap_merkle_root = tr.spend_info(&secp).merkle_root();
                    if let Some(taptree) = tr.taptree() {
                        descriptor.for_each_key(|key| {
                            let (pubkey, key_source) = key
                                .as_key()
                                .bip32_derivation(&secp, &input.terminal)
                                .expect("failing on second pass of the same function");
                            let mut leaves = vec![];
                            for (_, ms) in taptree.iter() {
                                for pk in ms.iter_pk() {
                                    if pk == pubkey {
                                        leaves.push(TapLeafHash::from_script(
                                            &ms.encode(),
                                            LeafVersion::TapScript,
                                        ));
                                    }
                                }
                            }
                            let entry = psbt_input
                                .tap_key_origins
                                .entry(pubkey.to_x_only_pubkey())
                                .or_insert((vec![], key_source));
                            entry.0.extend(leaves);
                            true
                        });
                    }
                    descriptor.for_each_key(|key| {
                        let (pubkey, key_source) = key
                            .as_key()
                            .bip32_derivation(&secp, &input.terminal)
                            .expect("failing on second pass of the same function");
                        if pubkey == *tr.internal_key() {
                            psbt_input
                                .tap_key_origins
                                .entry(pubkey.to_x_only_pubkey())
                                .or_insert((vec![], key_source));
                        }
                        true
                    });
                } else {
                    if dtype.has_redeem_script() {
                        psbt_input.redeem_script = Some(lock_script.clone());
                    }
                    if dtype.has_witness_script() {
                        psbt_input.witness_script = Some(lock_script);
                    }
                }
                Ok(psbt_input)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut psbt_outputs: Vec<_> = outputs.iter().map(|_| Output::default()).collect();

        let total_sent: u64 = outputs.iter().map(|output| output.amount.as_sat()).sum();

        let change = match total_spent.checked_sub(total_sent + fee) {
            Some(change) => change,
            None => {
                return Err(Error::Inflation {
                    input: total_spent,
                    output: total_sent + fee,
                })
            }
        };

        if change > 0 {
            let change_derivation = [UnhardenedIndex::one(), change_index];
            let change_descriptor = descriptor.derive_descriptor(&secp, &change_derivation)?;
            let change_address = change_descriptor.address(network)?;
            outputs.push(AddressAmount {
                address: change_address,
                amount: Amount::from_sat(change),
            });
            let mut bip32_derivation = bmap! {};
            descriptor.for_each_key(|key| {
                let pubkeychain = key.as_key();
                let (pubkey, key_source) = pubkeychain
                    .bip32_derivation(&secp, &change_derivation)
                    .expect("already tested descriptor derivation mismatch");
                bip32_derivation.insert(pubkey, key_source);
                true
            });

            let lock_script = change_descriptor.explicit_script()?;
            let dtype = descriptors::FullType::from(&change_descriptor);
            let mut psbt_change_output = Output {
                bip32_derivation,
                ..Default::default()
            };
            if dtype.has_redeem_script() {
                psbt_change_output.redeem_script = Some(lock_script.clone());
            }
            if dtype.has_witness_script() {
                psbt_change_output.witness_script = Some(lock_script);
            }
            psbt_outputs.push(psbt_change_output);
        }

        let spending_tx = Transaction {
            version: 2,
            lock_time: lock_time.as_u32(),
            input: inputs
                .iter()
                .map(|input| TxIn {
                    previous_output: input.outpoint,
                    sequence: input.seq_no.as_u32(),
                    ..Default::default()
                })
                .collect(),
            output: outputs
                .into_iter()
                .map(|output| TxOut {
                    value: output.amount.as_sat(),
                    script_pubkey: output.address.script_pubkey(),
                })
                .collect(),
        };

        let psbt = Psbt {
            unsigned_tx: spending_tx,
            version: 0,
            xpub,
            proprietary: none!(),
            unknown: none!(),

            inputs: psbt_inputs,
            outputs: psbt_outputs,
        };

        let file = fs::File::create(psbt_path)?;
        psbt.consensus_encode(file)?;

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
                "{}",
                tx.strict_serialize()
                    .expect("memory encoders does not error")
                    .to_hex()
            );
        }

        if let Some(network) = publish {
            let client = self.electrum_client(network)?;
            client.transaction_broadcast(&tx)?;
            eprintln!("{}\n", "Transaction published".bright_yellow());
        }

        Ok(())
    }

    fn inspect(path: &Path) -> Result<(), Error> {
        let file = fs::File::open(path)?;
        let psbt = Psbt::strict_decode(&file)?;
        println!("{}", serde_yaml::to_string(&psbt)?);
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

    #[from]
    Yaml(serde_yaml::Error),

    #[from]
    PsbtFinalization(miniscript::psbt::Error),

    /// unrecognized number of wildcards in the descriptor derive pattern
    #[display(doc_comments)]
    DescriptorDerivePattern,

    /// transaction id {0} is not found
    #[display(doc_comments)]
    TransactionUnknown(Txid),

    /// transaction id {0} does not have output number {1}
    #[display(doc_comments)]
    OutputUnknown(Txid, u32),

    /// derived scriptPubkey `{3}` does not match transaction scriptPubkey
    /// `{2}` for {0}:{1}
    #[display(doc_comments)]
    ScriptPubkeyMismatch(Txid, u32, Script, Script),

    /// the transaction can't be created according to the consensus rules since
    /// it spends more ({output} sats) than the sum of its input amounts
    /// ({input} sats)
    #[display(doc_comments)]
    Inflation {
        /// Amount spent: input amounts
        input: u64,

        /// Amount sent: sum of output value + transaction fee
        output: u64,
    },
}

fn main() -> Result<(), Error> {
    let args = Args::parse();
    args.exec()
}
