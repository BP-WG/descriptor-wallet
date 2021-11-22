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

use std::path::{Path, PathBuf};
use std::{fs, io};

use aes::cipher::generic_array::GenericArray;
use aes::{Aes256, Block, BlockDecrypt, BlockEncrypt, NewBlockCipher};
use amplify::IoError;
use bip39::Mnemonic;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::rand;
use bitcoin::secp256k1::rand::RngCore;
use clap::Parser;
use wallet::hd::{DerivationScheme, HardenedIndex};

/// Global bitcoin networks having bitcoin-consensus-compatible transactions.
/// This does not include on-premise networks like regtest or custom signet.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[repr(u8)]
pub enum Network {
    /// Bitcoin mainnet
    #[display("bitcoin")]
    Bitcoin,

    /// Bitcoin testnet v3
    #[display("testnet")]
    Testnet3,

    /// Bitcoin signet
    #[display("signet")]
    Signet,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[repr(u16)]
pub enum SeedType {
    Bit128 = 128,
    Bit160 = 160,
    Bit192 = 192,
    Bit224 = 224,
    Bit256 = 256,
}

impl SeedType {
    #[inline]
    pub fn bit_len(self) -> usize { self as usize }

    #[inline]
    pub fn byte_len(self) -> usize {
        match self {
            SeedType::Bit128 => 16,
            SeedType::Bit160 => 160 / 8,
            SeedType::Bit192 => 192 / 8,
            SeedType::Bit224 => 224 / 8,
            SeedType::Bit256 => 32,
        }
    }

    #[inline]
    pub fn word_len(self) -> usize {
        match self {
            SeedType::Bit128 => 12,
            SeedType::Bit160 => 15,
            SeedType::Bit192 => 18,
            SeedType::Bit224 => 21,
            SeedType::Bit256 => 24,
        }
    }
}

pub struct Seed(Box<[u8]>);

impl Seed {
    pub fn with(seed_type: SeedType) -> Seed {
        let mut entropy = vec![0u8; seed_type.byte_len()];
        rand::thread_rng().fill_bytes(&mut entropy);
        Seed(Box::from(entropy))
    }

    pub fn read<P>(file: P, password: &str) -> io::Result<Seed>
    where
        P: AsRef<Path>,
    {
        let key = sha256::Hash::hash(password.as_bytes());
        let key = GenericArray::from_slice(key.as_inner());
        let cipher = Aes256::new(key);

        let mut data = fs::read(file)?;
        let mut block = Block::from_mut_slice(&mut data);
        cipher.decrypt_block(block);
        Ok(Seed(Box::from(block.as_slice())))
    }

    pub fn write<P>(&self, file: P, password: &str) -> io::Result<()>
    where
        P: AsRef<Path>,
    {
        let key = sha256::Hash::hash(password.as_bytes());
        let key = GenericArray::from_slice(key.as_inner());
        let cipher = Aes256::new(key);

        let mut data = self.0.clone();
        let block = Block::from_mut_slice(&mut data);
        cipher.encrypt_block(block);

        fs::write(file, &block)
    }

    #[inline]
    pub fn as_entropy(&self) -> &[u8] { &self.0 }
}

/// Command-line arguments
#[derive(Parser)]
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[clap(
    author,
    version,
    name = "btc-hot",
    about = "Command-line file-based bitcoin hot wallet"
)]
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

impl Command {
    pub fn exec(&self) -> Result<(), Error> {
        match self {
            Command::Seed { output_file } => Command::seed(output_file),
            Command::Derive {
                seed_file,
                scheme,
                account,
                mainnet,
                testnet,
                signet,
                output_file,
            } => {
                let network = match (mainnet, testnet, signet) {
                    (true, false, false) => Network::Bitcoin,
                    (false, true, false) => Network::Testnet3,
                    (false, false, true) => Network::Signet,
                    _ => unreachable!(
                        "Clap unable to parse mutually exclusive network flags"
                    ),
                };
                Command::derive(
                    seed_file,
                    scheme,
                    *account,
                    network,
                    output_file,
                )
            }
            Command::Info { file } => Command::info(file),
            Command::Sign {
                psbt_file,
                signing_account,
            } => Command::sign(psbt_file, signing_account),
        }
    }

    fn seed(output_file: &PathBuf) -> Result<(), Error> {
        let seed = Seed::with(SeedType::Bit128);
        let password = rpassword::read_password_from_tty(Some("Password: "))?;
        seed.write(output_file, &password)?;

        let mnemonic = Mnemonic::from_entropy(seed.as_entropy())?;
        println!("{}\n", mnemonic);

        Ok(())
    }

    fn derive(
        seed_file: &PathBuf,
        scheme: &DerivationScheme,
        account: HardenedIndex,
        network: Network,
        output_file: &PathBuf,
    ) -> Result<(), Error> {
        let data = fs::read(seed_file)?;
        todo!()
    }

    fn info(file: &PathBuf) -> Result<(), Error> { todo!() }

    fn sign(
        psbt_file: &PathBuf,
        signing_account: &PathBuf,
    ) -> Result<(), Error> {
        todo!()
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(inner)]
pub enum Error {
    #[from(io::Error)]
    Io(IoError),

    #[from]
    Bip39(bip39::Error),
}

fn main() -> Result<(), Error> {
    let args = Args::parse();
    args.command.exec()
}
