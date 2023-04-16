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
use bitcoin::util::taproot::LeafVersion;
use bitcoin::{consensus, Address, EcdsaSig, LockTime, Network, PublicKey, Script, Txid};
use bitcoin_blockchain::locks::SeqNo;
use bitcoin_scripts::address::{AddressCompat, AddressFormat};
use bitcoin_scripts::TaprootWitness;
use clap::Parser;
use colored::Colorize;
use electrum_client as electrum;
use electrum_client::ElectrumApi;
use miniscript_crate::{Legacy, Miniscript, Segwitv0, Tap};

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

        println!("\nTransaction {}", txid.to_string().bright_white());
        println!("Version {:#x}", tx.version);
        let lock_time = LockTime::from(tx.lock_time);
        println!("Lock time {lock_time:#} ({:#010x})", tx.lock_time.to_u32());

        let weight = tx.weight();
        let size = tx.size();
        let mut witness_size = 0usize;
        let mut total_in = 0u64;
        let mut total_out = 0u64;
        let prev_txs = electrum
            .batch_transaction_get(tx.input.iter().map(|txin| &txin.previous_output.txid))?;

        println!();
        for (vin, (prev_tx, txin)) in prev_txs.into_iter().zip(tx.input).enumerate() {
            witness_size += txin.witness.iter().map(<[u8]>::len).sum::<usize>();

            let prevout = &prev_tx.output[txin.previous_output.vout as usize];
            println!(
                "{} {} <- {}",
                (vin + 1).to_string().bright_white(),
                "input".bright_white(),
                txin.previous_output
            );

            let seq = SeqNo::from_consensus(txin.sequence.to_consensus_u32());
            println!("  sequence value is {seq}");

            total_in += prevout.value;
            let btc = prevout.value / SATS_IN_BTC;
            println!(
                "  spending {} BTC, {} sats",
                btc.to_string().bright_yellow(),
                (prevout.value - btc * SATS_IN_BTC)
                    .to_string()
                    .bright_yellow()
            );
            let prev_addr = AddressCompat::from_script(
                &prevout.script_pubkey.clone().into(),
                self.network.into(),
            );
            match (prev_addr, prevout.script_pubkey.witness_version()) {
                (Some(addr), None) => {
                    let format = AddressFormat::from(Address::from(addr));
                    println!("  from {format} output addr({addr})")
                }
                (Some(addr), Some(ver)) => {
                    let format = AddressFormat::from(Address::from(addr));
                    println!("  from {format} SegWit v{ver} output addr({addr})")
                }
                (None, Some(ver)) => println!("  from non-standard SegWit v{ver}"),
                _ => println!("  from non-standard bare script"),
            };
            println!("    {}", prevout.script_pubkey);

            match prevout.script_pubkey.witness_version() {
                None => {
                    println!("  script {}", txin.script_sig);
                    match Miniscript::<_, Legacy>::parse_insane(&txin.script_sig) {
                        Ok(ms) => println!("    miniscript {ms}"),
                        Err(err) => eprintln!(
                            "    {}: {err}",
                            "non-representable in miniscript".bright_red()
                        ),
                    }
                }
                Some(WitnessVersion::V1) if prevout.script_pubkey.is_v1_p2tr() => {
                    let tw = TaprootWitness::try_from(txin.witness)
                        .expect("consensus-invalid taproot witness");
                    let annex = match tw {
                        TaprootWitness::PubkeySpending { sig, annex } => {
                            println!("  key path spending is used");
                            println!("  signature {}", sig.hash_ty.to_string().bright_green());
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
                            if script.version == LeafVersion::TapScript {
                                match Miniscript::<_, Tap>::parse_insane(&script.script) {
                                    Ok(ms) => println!("    miniscript {ms}"),
                                    Err(err) => eprintln!(
                                        "    {}: {err}",
                                        "non-representable in miniscript".bright_red()
                                    ),
                                }
                            }
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
                Some(WitnessVersion::V0) if prevout.script_pubkey.is_v0_p2wpkh() => {
                    let mut iter = txin.witness.iter();
                    let Some(sersig) = iter.next() else {
                        eprintln!("  {}", "invalid witness structure for P2WPK output".bright_red());
                        continue;
                    };
                    let Ok(sig) = EcdsaSig::from_slice(sersig) else {
                        eprintln!("    {} {}", "invalid signature".bright_red(), sersig.to_hex());
                        continue;
                    };
                    let Some(serpk) = iter.next() else {
                        eprintln!("  {}", "invalid witness structure for P2WPK output".bright_red());
                        continue;
                    };
                    let Ok(pk) = PublicKey::from_slice(serpk) else {
                        eprintln!("    {} {}", "invalid public key".bright_red(), serpk.to_hex());
                        continue;
                    };
                    println!("  wpkh({pk})");
                    println!(
                        "  witness signature {}",
                        sig.hash_ty.to_string().bright_green()
                    );
                    let h = sig.sig.to_string();
                    let (r, s) = h.split_at(64);
                    println!("    r {r}");
                    println!("    s {s}");
                    println!("  witness pubkey {}", pk);
                    if iter.count() > 0 {
                        eprintln!(
                            "  {}",
                            "invalid witness containing extra data for P2WPK".bright_red()
                        );
                    }
                }
                Some(WitnessVersion::V0) if prevout.script_pubkey.is_v0_p2wsh() => {
                    let mut witness = txin.witness.iter().collect::<Vec<_>>();
                    let Some(script_slice) = witness.pop() else {
                        eprintln!("  {}", "invalid P2WSH empty witness".bright_red());
                        continue;
                    };
                    let script = Script::from(script_slice.to_vec());
                    println!("  witness script {}", script_slice.to_hex());
                    println!("    {}", script);
                    match Miniscript::<_, Segwitv0>::parse_insane(&script) {
                        Ok(ms) => println!("    miniscript {ms}"),
                        Err(err) => eprintln!(
                            "    {}: {err}",
                            "non-representable in miniscript".bright_red()
                        ),
                    }

                    println!("  script inputs from witness:");
                    let mut i = 0;
                    while i < witness.len() {
                        // Signature
                        if let Ok(sig) = EcdsaSig::from_slice(witness[i]) {
                            println!("  - signature {}", sig.hash_ty.to_string().bright_green());
                            let h = sig.sig.serialize_compact().to_hex();
                            let (r, s) = h.split_at(64);
                            println!("    r {r}");
                            println!("    s {s}");
                        }
                        // public key
                        else if let Ok(pk) = PublicKey::from_slice(witness[i]) {
                            println!("  - public key {pk}");
                        }
                        // Preimage
                        else if witness[i].len() == 32 {
                            println!("  - possible hash preimage {}", witness[i].to_hex());
                        } else if witness[0].is_empty() {
                            println!("  - <empty item>");
                        } else {
                            println!("  - {}", witness[i].to_hex());
                        }
                        i += 1;
                    }
                }
                Some(WitnessVersion::V0) => {
                    eprintln!("  {}", "consensus-invalid witness v0".bright_red())
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
                "{} {} of {} BTC, {} sats",
                (vout + 1).to_string().bright_white(),
                "output".bright_white(),
                btc.to_string().bright_yellow(),
                (txout.value - btc * SATS_IN_BTC)
                    .to_string()
                    .bright_yellow()
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

        println!("Transaction weight is {} vbytes", weight);
        println!("  size is {} bytes", size);
        println!("  witness data size is {} bytes", witness_size);
        let fee = total_in - total_out;
        let btc_in = total_in / SATS_IN_BTC;
        let btc_out = total_out / SATS_IN_BTC;
        println!(
            "Transaction spends {} BTC {} sats",
            btc_in.to_string().bright_yellow(),
            (total_in - btc_in * SATS_IN_BTC)
                .to_string()
                .bright_yellow()
        );
        println!(
            "  paying {} sats in fees ({:.2} sats per vbyte)",
            fee.to_string().bright_yellow(),
            fee as f32 / weight as f32
        );
        println!(
            "  sending {btc_out} BTC {} sats to its outputs",
            total_out - btc_out * SATS_IN_BTC
        );
        println!();

        if let Ok(info) = electrum.transaction_get_merkle(txid, 0) {
            if info.block_height == 0 {
                println!("Transaction is not mined yet and exists in mempool");
            } else {
                println!("Mined at height {}", info.block_height);
                println!("  Block position is {}", info.pos);
                println!("  Transaction inclusion Merkle path proof:");
                for node in info.merkle {
                    println!("    {}", node.to_hex());
                }
            }
        } else {
            eprintln!(
                "{}: the used electrum backend doesn't provide mining info by a txid
  use esplora-powered backends to get addition info about the transaction",
                "Warning".bright_yellow()
            );
        }
        println!();

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
