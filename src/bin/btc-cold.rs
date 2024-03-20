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

#[macro_use]
extern crate clap;
#[macro_use]
extern crate amplify;

#[cfg(feature = "miniscript")]
extern crate miniscript_crate as miniscript;
extern crate strict_encoding_crate as strict_encoding;

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::fmt::{Debug, Display, Formatter, Write};
use std::io::{stdin, stdout, BufRead, BufReader, Write as IoWrite};
use std::num::ParseIntError;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{fmt, fs, io};

use amplify::hex::ToHex;
use amplify::{IoError, Wrapper};
use bitcoin::consensus::Encodable;
use bitcoin::psbt::serialize::Serialize;
use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::address;
use bitcoin::util::bip32::{ChildNumber, ExtendedPubKey};
use bitcoin::{consensus, Address, Network};
use bitcoin_blockchain::locks::LockTime;
use bitcoin_hd::DeriveError;
use bitcoin_onchain::UtxoResolverError;
use bitcoin_scripts::address::AddressCompat;
use bitcoin_scripts::PubkeyScript;
use clap::Parser;
use colored::Colorize;
use descriptors::derive::Descriptor;
use electrum_client as electrum;
use electrum_client::ElectrumApi;
use miniscript::psbt::PsbtExt;
use miniscript::{MiniscriptKey, TranslatePk};
use miniscript_crate::Translator;
use psbt::serialize::Deserialize;
use psbt::{construct, ProprietaryKeyDescriptor, ProprietaryKeyError, ProprietaryKeyLocation};
use slip132::{
    DefaultResolver, FromSlip132, KeyApplication, KeyVersion, ToSlip132, VersionResolver,
};
use wallet::descriptors::InputDescriptor;
use wallet::hd::{DerivationAccount, SegmentIndexes, UnhardenedIndex};
use wallet::onchain::ResolveDescriptor;
use wallet::psbt::{Psbt, PsbtParseError};

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

    /// Use Bitcoin Core descriptor representation.
    #[clap(long = "bitcoin-core-fmt", global = true)]
    pub bitcoin_core_fmt: bool,
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
        /// File containing named tracking account definitions, one per line.
        ///
        /// Account name must go first and should be separated by a whitespace
        /// from tracking account descriptor.
        #[clap(long)]
        account_file: Option<PathBuf>,

        /// Wallet output descriptor text file. Can use explicit or named
        /// tracking accounts; in the second case please provide
        /// `--account-file` parameter.
        ///
        /// Descriptor can use taproot and miniscript.
        descriptor_file: PathBuf,

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

        /// Show addresses using regtest prefix. Works only for testnet-based
        /// wallet descriptors.
        #[clap(long = "regtest")]
        regtest: bool,
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

        /// Display address using regtest prefix. Works only for testnet-based
        /// descriptors.
        #[clap(long = "regtest")]
        regtest: bool,
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
- `height(NO)`: allow the transaction to be mined with sequence lock
  set to `NO` blocks (required for miniscript `older` satisfaction);
- `time(NO)`: allow the transaction to be mined if it is older then
  the provided number `NO` of 5-minute intervals (required for miniscript 
  `after` satisfaction).

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
        #[clap(short, long = "output")]
        outputs: Vec<AddressAmount>,

        /// Derivation index for change address
        #[clap(short, long, default_value = "0")]
        change_index: UnhardenedIndex,

        /// Additional proprietary keys which will be added to the constructed
        /// PSBT.
        #[clap(short = 'k', long = "proprietary-key")]
        proprietary_keys: Vec<ProprietaryKeyDescriptor>,

        /// Destination file to save constructed PSBT
        psbt_file: PathBuf,

        /// Total fee to pay to the miners, in satoshis.
        ///
        /// The fee is used in change calculation; the change address is
        /// added automatically.
        fee: u64,
    },

    /// Try to finalize PSBT
    Finalize {
        /// Destination file to save binary transaction. If no file is given
        /// the transaction is print to the screen in hex form.
        #[clap(short = 'o', long = "output")]
        tx_file: Option<PathBuf>,

        /// Publish the transaction to the network; optional argument allows
        /// to specify some custom network (testnet, for instance).
        #[clap(long)]
        publish: Option<Option<Network>>,

        /// File containing fully-signed PSBT
        psbt_file: PathBuf,
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
                account_file,
                descriptor_file,
                output_file,
            } => Self::create(descriptor_file, output_file, account_file.as_deref()),
            Command::Check {
                wallet_file,
                look_ahead,
                skip,
                regtest,
            } => self.check(wallet_file, *look_ahead, *skip, *regtest),
            Command::History { .. } => self.history(),
            Command::Address {
                wallet_file,
                count,
                skip,
                show_change,
                regtest,
            } => self.address(wallet_file, *count, *skip, *show_change, *regtest),
            Command::Construct {
                locktime,
                wallet_file,
                inputs,
                outputs,
                change_index,
                proprietary_keys,
                psbt_file,
                fee,
            } => self.construct(
                wallet_file,
                *locktime,
                inputs,
                outputs,
                *change_index,
                proprietary_keys,
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

    fn create(
        descriptor_file: &Path,
        path: &Path,
        account_file: Option<&Path>,
    ) -> Result<(), Error> {
        pub struct DerivationRefTranslator<'a> {
            account_file: Option<&'a Path>,
            accounts: &'a AccountIndex,
        }

        impl<'a> Translator<DerivationRef, DerivationAccount, Error> for DerivationRefTranslator<'a> {
            fn pk(&mut self, pk: &DerivationRef) -> Result<DerivationAccount, Error> {
                match pk {
                    DerivationRef::NamedAccount(_) if self.account_file.is_none() => {
                        Err(Error::AccountsFileRequired)
                    }
                    DerivationRef::NamedAccount(name) => self
                        .accounts
                        .get(name.as_str())
                        .cloned()
                        .ok_or_else(|| Error::UnknownNamedAccount(name.clone())),
                    DerivationRef::TrackingAccount(account) => Ok(account.clone()),
                }
            }

            miniscript::translate_hash_fail!(DerivationRef, DerivationAccount, Error);
        }

        let accounts = account_file
            .and_then(AccountIndex::read_file)
            .unwrap_or_default();

        let descriptor_str =
            fs::read_to_string(descriptor_file)?.replace(['\n', '\r', ' ', '\t'], "");
        println!(
            "Creating wallet for descriptor:\n{}",
            descriptor_str.bright_white()
        );
        let descriptor = miniscript::Descriptor::<DerivationRef>::from_str(&descriptor_str)?;
        let descriptor = descriptor.translate_pk(&mut DerivationRefTranslator {
            account_file,
            accounts: &accounts,
        })?;

        fs::write(path, descriptor.to_string())?;

        println!(
            "{} in `{}`\n",
            "Wallet created".bright_green(),
            path.display()
        );

        Ok(())
    }

    fn address(
        &self,
        path: &Path,
        count: u16,
        skip: u16,
        show_change: bool,
        regtest: bool,
    ) -> Result<(), Error> {
        let secp = Secp256k1::new();

        let descriptor_str = fs::read_to_string(path)?;
        let descriptor: miniscript::Descriptor<DerivationAccount> =
            miniscript::Descriptor::from_str(&descriptor_str)?;

        println!(
            "{}\n{}\n",
            "\nWallet descriptor:".bright_white(),
            descriptor.to_string_std(self.bitcoin_core_fmt)
        );

        if descriptor.derive_pattern_len()? != 2 {
            return Err(Error::DescriptorDerivePattern);
        }
        for index in skip..(skip + count) {
            let address = descriptor.address(
                &secp,
                [
                    UnhardenedIndex::from(u8::from(show_change)),
                    UnhardenedIndex::from(index),
                ],
                regtest,
            )?;

            println!("{:>6} {}", format!("#{}", index).dimmed(), address);
        }

        println!();

        Ok(())
    }

    fn check(&self, path: &Path, batch_size: u16, skip: u16, regtest: bool) -> Result<(), Error> {
        let secp = Secp256k1::new();

        let descriptor_str = fs::read_to_string(path)?;
        let descriptor: miniscript::Descriptor<DerivationAccount> =
            miniscript::Descriptor::from_str(&descriptor_str)?;

        let network = descriptor.network(regtest)?;
        let client = self.electrum_client(network)?;

        println!(
            "{}\n{}\n",
            "\nWallet descriptor:".bright_white(),
            descriptor.to_string_std(self.bitcoin_core_fmt)
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
                if let Some(idx) = derive_pattern.first_mut() {
                    *idx = UnhardenedIndex::from(case)
                }
            }
            loop {
                eprint!("Batch {}/{}..{}", case, offset, offset + batch_size);

                let mut addr_total = 0u64;
                let mut count = 0usize;
                eprint!(" ... ");
                for (index, (script, utxo_set)) in client.resolve_descriptor_utxo(
                    &secp,
                    &descriptor,
                    [UnhardenedIndex::from(case)],
                    UnhardenedIndex::from(offset),
                    batch_size as u32,
                )? {
                    if utxo_set.is_empty() {
                        continue;
                    }
                    count += utxo_set.len();

                    let derive_term = format!("{}/{}", case, index);
                    if let Some(address) =
                        AddressCompat::from_script(&script.clone().into(), network.into())
                    {
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

                    for utxo in utxo_set {
                        println!(
                            "{:>10} @ {} - {}",
                            utxo.amount().to_string().bright_yellow(),
                            utxo.outpoint(),
                            utxo.mined()
                        );
                        addr_total += utxo.amount().to_sat();
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
        println!("{:-13} {}", "Fingerprint:", xpub.fingerprint());
        println!("{:-13} {}", "Identifier:", xpub.identifier());
        println!("{:-13} {}", "Network:", xpub.network);
        println!("{:-13} {}", "Public key:", xpub.public_key);
        println!("{:-13} {}", "Chain code:", xpub.chain_code);
        match KeyVersion::from_xkey_str(data) {
            Ok(ver) => {
                if let Some(application) = DefaultResolver::application(&ver) {
                    println!("{:-13} {}", "Application:", application);
                }
                if let Some(derivation_path) = DefaultResolver::derivation_path(&ver, None) {
                    println!("{:-13} {}", "Derivation:", derivation_path);
                } else if let Some(derivation_path) =
                    DefaultResolver::derivation_path(&ver, Some(ChildNumber::Hardened { index: 0 }))
                {
                    println!("{:-13} {}  # (account 0)", "Derivation:", derivation_path);
                }
            }
            Err(err) => eprintln!(
                "{:-13} {} {}",
                "Application:",
                "unable to read SLIP-132 information.".bright_red(),
                err
            ),
        }
        println!("{:-13} {}", "Depth:", xpub.depth);
        println!("{:-13} {:#}", "Child number:", xpub.child_number);
        println!("Variants:");
        for network in [bitcoin::Network::Bitcoin, bitcoin::Network::Testnet] {
            for app in KeyApplication::ALL {
                println!("  - {}", xpub.to_slip132_string(app, network));
            }
        }
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
        proprietary_keys: &[ProprietaryKeyDescriptor],
        fee: u64,
        psbt_path: &Path,
    ) -> Result<(), Error> {
        let descriptor_str = fs::read_to_string(wallet_path)?;
        let descriptor: miniscript::Descriptor<DerivationAccount> =
            miniscript::Descriptor::from_str(&descriptor_str)?;

        let network = descriptor.network(false)?;
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
            .map(|a| {
                (
                    PubkeyScript::from_inner(a.address.script_pubkey()),
                    a.amount,
                )
            })
            .collect::<Vec<_>>();

        let mut psbt = Psbt::construct(&descriptor, inputs, &outputs, change_index, fee, &tx_map)?;
        psbt.fallback_locktime = Some(lock_time);

        for key in proprietary_keys {
            match key.location {
                ProprietaryKeyLocation::Input(pos) if pos as usize >= psbt.inputs.len() => {
                    return Err(ProprietaryKeyError::InputOutOfRange(pos, psbt.inputs.len()).into())
                }
                ProprietaryKeyLocation::Output(pos) if pos as usize >= psbt.outputs.len() => {
                    return Err(
                        ProprietaryKeyError::OutputOutOfRange(pos, psbt.inputs.len()).into(),
                    )
                }
                ProprietaryKeyLocation::Global => {
                    psbt.proprietary
                        .insert(key.into(), key.value.as_ref().cloned().unwrap_or_default());
                }
                ProprietaryKeyLocation::Input(pos) => {
                    psbt.inputs[pos as usize]
                        .proprietary
                        .insert(key.into(), key.value.as_ref().cloned().unwrap_or_default());
                }
                ProprietaryKeyLocation::Output(pos) => {
                    psbt.outputs[pos as usize]
                        .proprietary
                        .insert(key.into(), key.value.as_ref().cloned().unwrap_or_default());
                }
            }
        }

        fs::write(psbt_path, psbt.serialize())?;

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

        let data = fs::read(psbt_path)?;
        let mut psbt = consensus::encode::deserialize::<PartiallySignedTransaction>(&data)
            .map_err(Error::psbt_from_consensus)?;

        psbt.finalize_mut(&secp).map_err(VecDisplay::from)?;

        let tx = psbt.extract_tx();

        if let Some(tx_path) = tx_path {
            let mut file = fs::File::create(tx_path)?;
            tx.consensus_encode(&mut file)?;
        } else {
            println!("{}\n", tx.serialize().to_hex());
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
            let data = fs::read(path)?;
            Psbt::deserialize(&data).map_err(Error::psbt_from_consensus)?
        } else {
            eprint!("Type in Base58 encoded PSBT and press enter: ");
            stdout().flush()?;
            let stdin = stdin();
            let psbt64 = stdin.lock().lines().next().expect("no PSBT data")?;
            Psbt::from_str(psbt64.trim())?
        };
        println!("\n{}", serde_yaml::to_string(&psbt)?);
        Ok(())
    }

    fn convert(&self, path: &Path) -> Result<(), Error> {
        let data = fs::read(path)?;
        let psbt = Psbt::deserialize(&data).map_err(Error::psbt_from_consensus)?;
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

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[display(inner)]
#[allow(clippy::large_enum_variant)]
pub enum DerivationRef {
    #[from]
    TrackingAccount(DerivationAccount),
    #[from]
    NamedAccount(String),
}

pub type AccountIndex = BTreeMap<String, DerivationAccount>;

impl FromStr for DerivationRef {
    type Err = bitcoin_hd::account::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if s.contains(['[', '{', '/', '*']) {
            DerivationRef::TrackingAccount(DerivationAccount::from_str(s)?)
        } else {
            DerivationRef::NamedAccount(s.to_owned())
        })
    }
}

impl MiniscriptKey for DerivationRef {
    type Sha256 = Self;
    type Hash256 = Self;
    type Ripemd160 = Self;
    type Hash160 = Self;
}

trait ReadAccounts {
    fn read_file(path: impl AsRef<Path>) -> Option<Self>
    where
        Self: Sized;
}

impl ReadAccounts for AccountIndex {
    fn read_file(path: impl AsRef<Path>) -> Option<Self> {
        let path = path.as_ref();

        let file = fs::File::open(path)
            .map_err(|err| {
                eprintln!(
                    "{} opening accounts file `{}`: {}",
                    "Error".bright_red(),
                    path.display(),
                    err
                )
            })
            .ok()?;

        let reader = BufReader::new(file);

        let index = reader
            .lines()
            .enumerate()
            .filter_map(|(index, line)| match line {
                Err(err) => {
                    eprintln!(
                        "{} in `{}` line #{}: {}",
                        "Error".bright_red(),
                        path.display(),
                        index + 1,
                        err
                    );
                    None
                }
                Ok(line) => {
                    let mut split = line.split_whitespace();
                    let name = split.next().map(str::to_owned);
                    let account = split.next().map(DerivationAccount::from_str);
                    match (name, account, split.next()) {
                        (Some(name), Some(Ok(account)), None) => Some((name, account)),
                        (_, Some(Err(err)), _) => {
                            eprintln!(
                                "{} in `{}` line #{}: {}",
                                "Error".bright_red(),
                                path.display(),
                                index + 1,
                                err
                            );
                            None
                        }
                        _ => {
                            eprintln!(
                                "{} in `{}` line #{}: each line must contain account name and \
                                 descriptor separated by a whitespace",
                                "Error".bright_red(),
                                path.display(),
                                index + 1
                            );
                            None
                        }
                    }
                }
            })
            .collect();

        Some(index)
    }
}

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum Error {
    #[from(io::Error)]
    Io(IoError),

    #[from]
    PsbtEncoding(psbt::Error),

    #[from]
    PsbtParse(PsbtParseError),

    #[from]
    Miniscript(miniscript::Error),

    #[from]
    Derive(DeriveError),

    #[from]
    ResolveUtxo(UtxoResolverError),

    #[from]
    Electrum(electrum::Error),

    #[from]
    Yaml(serde_yaml::Error),

    #[from]
    PsbtConstruction(construct::Error),

    /// can't finalize PSBT data due to following problem(s):
    ///
    /// {0}
    #[display(doc_comments)]
    #[from]
    PsbtFinalization(VecDisplay<miniscript::psbt::Error, true, '-', '\n'>),

    /// unrecognized number of wildcards in the descriptor derive pattern
    #[display(doc_comments)]
    DescriptorDerivePattern,

    /// error in extended key encoding: {0}
    #[from]
    #[display(doc_comments)]
    XkeyEncoding(slip132::Error),

    /// use of named accounts in wallet descriptor requires `--accounts-file`
    /// option
    #[display(doc_comments)]
    AccountsFileRequired,

    /// accounts file has no entry for `{0}` account used in wallet descriptor
    #[display(doc_comments)]
    UnknownNamedAccount(String),

    /// can't set proprietary key for PSBT {0}
    #[from]
    #[display(doc_comments)]
    PsbtProprietaryKey(ProprietaryKeyError),
}

impl Error {
    pub fn psbt_from_consensus(e: consensus::encode::Error) -> Error {
        match e {
            consensus::encode::Error::Psbt(e) => Error::PsbtEncoding(e),
            consensus::encode::Error::Io(e) => e.into(),
            err => unreachable!("{err:#?}"),
        }
    }
}

// TODO: Move to amplify crate
#[derive(Debug, From)]
pub struct VecDisplay<T, const PREFIX: bool, const PREFIX_CHAR: char, const JOIN_CHAR: char>(
    Vec<T>,
)
where
    T: Display + Debug;

impl<T, const PREFIX: bool, const PREFIX_CHAR: char, const JOIN_CHAR: char> Display
    for VecDisplay<T, PREFIX, PREFIX_CHAR, JOIN_CHAR>
where
    T: Display + Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let len = self.0.len();
        for (index, el) in self.0.iter().enumerate() {
            if PREFIX {
                write!(f, "{} ", PREFIX_CHAR)?;
            }
            Display::fmt(el, f)?;
            if index < len - 1 {
                f.write_char(JOIN_CHAR)?;
            }
        }
        Ok(())
    }
}

trait ToStringStd {
    fn to_string_std(&self, bitcoin_core_fmt: bool) -> String;
}

impl ToStringStd for miniscript::Descriptor<DerivationAccount> {
    fn to_string_std(&self, bitcoin_core_fmt: bool) -> String {
        struct StrTranslator;
        impl Translator<DerivationAccount, String, Infallible> for StrTranslator {
            fn pk(&mut self, pk: &DerivationAccount) -> Result<String, Infallible> {
                Ok(format!("{:#}", pk))
            }

            miniscript::translate_hash_fail!(DerivationAccount, String, Infallible);
        }

        if bitcoin_core_fmt {
            self.translate_pk(&mut StrTranslator)
                .expect("infallible")
                .to_string()
        } else {
            self.to_string()
        }
    }
}

fn main() {
    let args = Args::parse();
    if let Err(err) = args.exec() {
        eprintln!("{}: {}\n", "Error".bright_red(), err);
    }
}
