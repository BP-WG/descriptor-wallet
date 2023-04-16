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

#![allow(clippy::result_large_err)]

#[macro_use]
extern crate clap;
#[macro_use]
extern crate amplify;

use std::io;

use amplify::hex::ToHex;
use amplify::IoError;
use bitcoin::util::address::WitnessVersion;
use bitcoin::{consensus, Address, LockTime, Network, Txid};
use bitcoin_scripts::address::{AddressCompat, AddressFormat};
use bitcoin_scripts::TaprootWitness;
use clap::Parser;
use colored::Colorize;
use electrum_client as electrum;
use electrum_client::ElectrumApi;

/// Command-line arguments
#[derive(Parser)]
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[clap(
    author,
    version,
    name = "btc-expl",
    about = "Command-line bitcoin explorer"
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

    /// Publish the transaction to the network; optional argument allows
    /// to specify some custom network (testnet, for instance).
    #[clap(short, long, global = true, default_value = "bitcoin")]
    network: Network,
}

/// Wallet command to execute
#[derive(Subcommand)]
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum Command {
    /// Explore transaction
    Tx {
        /// Txid to lookup.
        txid: Txid,
    },
}

fn default_electrum_port(network: Network) -> u16 {
    match network {
        Network::Bitcoin => 50001,
        Network::Testnet => 60001,
        Network::Signet | Network::Regtest => 60601,
    }
}

const SATS_IN_BTC: u64 = 100_000_000;

impl Args {
    fn electrum_client(&self) -> Result<electrum::Client, electrum::Error> {
        let electrum_url = format!(
            "{}:{}",
            self.electrum_server,
            self.electrum_port
                .unwrap_or_else(|| default_electrum_port(self.network))
        );
        eprintln!(
            "Connecting to network {} using {}",
            self.network.to_string().yellow(),
            electrum_url.yellow()
        );
        electrum::Client::new(&electrum_url)
    }

    pub fn exec(self) -> Result<(), Error> {
        match &self.command {
            Command::Tx { txid } => self.tx(txid),
        }
    }

    fn tx(&self, txid: &Txid) -> Result<(), Error> {
        let electrum = self.electrum_client()?;
        let tx = electrum.transaction_get(txid)?;

        println!("\nTransaction {txid}");
        println!("Version {:#x}", tx.version);
        let lock_time = LockTime::from(tx.lock_time);
        println!("Lock time {lock_time:#} ({:#010x})", tx.lock_time.to_u32());

        let mut total_in = 0u64;
        let mut total_out = 0u64;
        let prev_txs = electrum
            .batch_transaction_get(tx.input.iter().map(|txin| &txin.previous_output.txid))?;
        for (vin, (prev_tx, txin)) in prev_txs.into_iter().zip(tx.input).enumerate() {
            let prevout = &prev_tx.output[txin.previous_output.vout as usize];
            println!("{} input <- {}", vin + 1, txin.previous_output);
            total_in += prevout.value;
            let btc = prevout.value / SATS_IN_BTC;
            println!(
                "  spending {btc} BTC, {} sats",
                prevout.value - btc * SATS_IN_BTC
            );
            let prev_addr = AddressCompat::from_script(
                &prevout.script_pubkey.clone().into(),
                self.network.into(),
            );
            match (prev_addr, prevout.script_pubkey.witness_version()) {
                (Some(addr), None) => {
                    let format = AddressFormat::from(Address::from(addr));
                    println!("  from {format} output ({addr})")
                }
                (Some(addr), Some(ver)) => {
                    let format = AddressFormat::from(Address::from(addr));
                    println!("  from {format} SegWit v{ver} output ({addr})")
                }
                (None, Some(ver)) => println!("  from non-standard SegWit v{ver}"),
                _ => println!("  from non-standard bare script"),
            };
            println!("    {}", prevout.script_pubkey);
            match prevout.script_pubkey.witness_version() {
                None => println!("  sigScript {}", txin.script_sig),
                Some(WitnessVersion::V1) if prevout.script_pubkey.is_v1_p2tr() => {
                    let tw = TaprootWitness::try_from(txin.witness)
                        .expect("consensus-invalid taproot witness");
                    let annex = match tw {
                        TaprootWitness::PubkeySpending { sig, annex } => {
                            println!("  key path spending is used");
                            println!("  signature {}", sig.hash_ty);
                            let h = sig.sig.to_hex();
                            let (r, s) = h.split_at(64);
                            println!("    r {r}");
                            println!("    s {s}");
                            annex
                        }
                        TaprootWitness::ScriptSpending {
                            control_block,
                            annex,
                            script,
                            script_input,
                        } => {
                            println!("  script path spending is used");
                            println!("    leaf version {}", control_block.leaf_version);
                            println!("    key parity: {:?}", control_block.output_key_parity);
                            println!("    internal key {}", control_block.internal_key);
                            println!(
                                "    merkle branch: {}",
                                control_block
                                    .merkle_branch
                                    .as_inner()
                                    .iter()
                                    .map(|node| node.to_hex())
                                    .collect::<Vec<_>>()
                                    .join("/")
                            );
                            println!("    leaf script {}", script.script);
                            println!("    script input(s):");
                            for el in script_input {
                                println!("      - {}", el.to_hex());
                            }
                            annex
                        }
                    };
                    if let Some(annex) = annex {
                        println!("  annex {}", annex.to_hex())
                    }
                }
                _ => {
                    println!("  witness stack:");
                    for el in txin.witness.iter() {
                        println!("    - {}", el.to_hex());
                    }
                }
            }
            println!();
        }

        for (vout, txout) in tx.output.iter().enumerate() {
            total_out += txout.value;
            let btc = txout.value / SATS_IN_BTC;
            println!(
                "{} output of {btc} BTC, {} sats",
                vout + 1,
                txout.value - btc * SATS_IN_BTC
            );
            println!("  locked with {}", txout.script_pubkey);
            let addr_compat = AddressCompat::from_script(
                &txout.script_pubkey.clone().into(),
                self.network.into(),
            );
            if let Some(addr) = addr_compat {
                println!("  addr({addr})");
            }
            println!();
        }

        let fee = total_in - total_out;
        let btc_in = total_in / SATS_IN_BTC;
        let btc_out = total_out / SATS_IN_BTC;
        println!(
            "Transaction spends {btc_in} BTC {} sats",
            total_in - btc_in * SATS_IN_BTC
        );
        println!("    paying {fee} sats in fees");
        println!(
            "    sending {btc_out} BTC {} sats to its outputs",
            total_out - btc_out * SATS_IN_BTC
        );
        Ok(())
    }
}

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum Error {
    #[from(io::Error)]
    Io(IoError),

    #[from]
    Encoding(consensus::encode::Error),

    #[from]
    Electrum(electrum::Error),
}

fn main() {
    let args = Args::parse();
    if let Err(err) = args.exec() {
        eprintln!("{}: {}\n", "Error".bright_red(), err);
    }
}
