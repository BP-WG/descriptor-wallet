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
use amplify::hex::ToHex;
use amplify::IoError;
use bip39::Mnemonic;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::rand::RngCore;
use bitcoin::secp256k1::{self, rand, Secp256k1, Signing};
use bitcoin::util::bip32;
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use clap::Parser;
use colored::Colorize;
use psbt::sign::{MemoryKeyProvider, MemorySigningAccount, SignAll, SignError};
use psbt::Psbt;
use slip132::{KeyApplication, ToSlip132};
use strict_encoding::{StrictDecode, StrictEncode};
use wallet::hd::schemata::DerivationBlockchain;
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

impl Network {
    #[inline]
    pub fn is_testnet(self) -> bool { self != Network::Bitcoin }
}

impl From<Network> for DerivationBlockchain {
    #[inline]
    fn from(network: Network) -> Self {
        match network {
            Network::Bitcoin => DerivationBlockchain::Bitcoin,
            Network::Testnet3 | Network::Signet => DerivationBlockchain::Testnet,
        }
    }
}

impl From<Network> for bitcoin::Network {
    fn from(network: Network) -> Self {
        match network {
            Network::Bitcoin => bitcoin::Network::Bitcoin,
            Network::Testnet3 => bitcoin::Network::Testnet,
            Network::Signet => bitcoin::Network::Signet,
        }
    }
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
        let block = Block::from_mut_slice(&mut data);
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
        let mut block2 = *block;
        cipher.decrypt_block(&mut block2);
        debug_assert_eq!(self.0.as_ref(), block2.as_slice());

        fs::write(file, &block)
    }

    #[inline]
    pub fn as_entropy(&self) -> &[u8] { &self.0 }

    #[inline]
    pub fn master_xpriv(&self, testnet: bool) -> Result<ExtendedPrivKey, bip32::Error> {
        ExtendedPrivKey::new_master(
            if testnet {
                bitcoin::Network::Testnet
            } else {
                bitcoin::Network::Bitcoin
            },
            self.as_entropy(),
        )
    }
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
    /// Print private information, including mnemonic, extended private keys and
    /// signatures
    #[clap(short = 'P', long, global = true)]
    pub print_private: bool,

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

        /// Derivation scheme.
        #[clap(
            short,
            long,
            long_help = "Possible values are:
- bip44: used for P2PKH (not recommended)
- bip84: used for P2WPKH
- bip49: used for P2WPKH-in-P2SH
- bip86: used for P2TR (Taproot!)
- bip45: used for legacy multisigs (P2SH, not recommended)
- bip48//1h: used for P2WSH-in-P2SH multisigs (deterministic order)
- bip48//2h: used for P2WSH multisigs (deterministic order)
- bip87: used for modern multisigs with descriptors (pre-MuSig)
- lnpbp43//<identity>h: identity-based wallets (multisig, taproot)
- bip43: non-standard purpose fields
- m/<derivation path>: custom derivation path",
            default_value = "bip86"
        )]
        scheme: DerivationScheme,

        /// Account derivation number (should be hardened, i.e. with `h` or `'`
        /// suffix).
        #[clap(short, long, default_value = "0'")]
        account: HardenedIndex,

        /// Use the seed for bitcoin mainnet
        #[clap(long, group = "network", required_unless_present_any = &["testnet", "signet"])]
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

    /// Derive a single key with a custom derivation path
    Key {
        // TODO: Replace with global verbosity flag
        /// Print detailed debug information
        #[clap(long)]
        debug: bool,

        /// Seed file containing extended master key, created previously with
        /// `seed` command.
        seed_file: PathBuf,

        /// Derivation path
        derivation: DerivationPath,
    },

    /// Print information about seed or the signing account.
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

impl Args {
    pub fn exec(self) -> Result<(), Error> {
        match &self.command {
            Command::Seed { output_file } => self.seed(output_file),
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
                    _ => unreachable!("Clap unable to parse mutually exclusive network flags"),
                };
                self.derive(seed_file, scheme, *account, network, output_file)
            }
            Command::Info { file } => self.info(file),
            Command::Sign {
                psbt_file,
                signing_account,
            } => self.sign(psbt_file, signing_account),
            Command::Key {
                debug,
                seed_file,
                derivation,
            } => self.key(seed_file, derivation, *debug),
        }
    }

    fn seed(&self, output_file: &Path) -> Result<(), Error> {
        let seed = Seed::with(SeedType::Bit128);
        let password = rpassword::read_password_from_tty(Some("Password: "))?;
        seed.write(output_file, &password)?;

        let secp = Secp256k1::new();
        self.info_seed(&secp, seed);

        Ok(())
    }

    fn derive(
        &self,
        seed_file: &Path,
        scheme: &DerivationScheme,
        account: HardenedIndex,
        network: Network,
        output_file: &Path,
    ) -> Result<(), Error> {
        let secp = Secp256k1::new();

        let seed_password = rpassword::read_password_from_tty(Some("Seed password: "))?;
        let seed = Seed::read(seed_file, &seed_password)?;
        let master_xpriv = seed.master_xpriv(network.is_testnet())?;
        let master_xpub = ExtendedPubKey::from_priv(&secp, &master_xpriv);
        let derivation = scheme.to_account_derivation(account.into(), network.into());
        let account_xpriv = master_xpriv.derive_priv(&secp, &derivation)?;

        let account =
            MemorySigningAccount::with(&secp, master_xpub.identifier(), derivation, account_xpriv);

        let file = fs::File::create(output_file)?;
        account.write(file)?;

        self.info_account(account);

        Ok(())
    }

    fn key(&self, seed_file: &Path, derivation: &DerivationPath, debug: bool) -> Result<(), Error> {
        let secp = Secp256k1::new();

        let seed_password = rpassword::read_password_from_tty(Some("Seed password: "))?;
        let seed = Seed::read(seed_file, &seed_password)?;
        let master_xpriv = seed.master_xpriv(false)?;
        let master_xpub = ExtendedPubKey::from_priv(&secp, &master_xpriv);
        let account = MemorySigningAccount::with(
            &secp,
            master_xpub.identifier(),
            DerivationPath::master(),
            master_xpriv,
        );
        let seckey = account.derive_seckey(&secp, derivation);
        let keypair = account.derive_keypair(&secp, derivation);
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &seckey);
        let xonly = secp256k1::XOnlyPublicKey::from_keypair(&keypair);

        println!("{}", "Derivation:".bright_white());
        println!(
            "{:-18} {}",
            "  - master xpubid:".bright_white(),
            master_xpub.identifier()
        );
        println!(
            "{:-18} {}{}",
            "  - derivation:".bright_white(),
            format!("m=[{}]/", master_xpub.fingerprint()).bright_yellow(),
            format!("{:#}", derivation)
                .trim_start_matches("m/")
                .bright_yellow()
        );

        println!();
        println!("{}", "Public keys:".bright_white());
        println!(
            "{:-18} {}",
            "  - compressed:".bright_white(),
            pubkey.to_string().bright_green()
        );
        println!(
            "{:-18} {}",
            "  - uncompressed:".bright_white(),
            pubkey.serialize_uncompressed().to_hex()
        );
        println!("{:-18} {}", "  - x-coord only:".bright_white(), xonly);
        if debug {
            println!("{:-18} {:?}", "  - platform repr:", pubkey);
        }
        if self.print_private {
            println!();
            println!(
                "{:-18} {}",
                "Private key:".bright_red(),
                seckey.display_secret().to_string().black().dimmed()
            );
        }
        println!();

        Ok(())
    }

    fn info_seed<C>(&self, secp: &Secp256k1<C>, seed: Seed)
    where
        C: Signing,
    {
        if self.print_private {
            let mnemonic = Mnemonic::from_entropy(seed.as_entropy()).expect("invalid seed");
            println!(
                "\n{:-18} {}",
                "Mnemonic:".bright_white(),
                mnemonic.to_string().bright_red()
            );
        }

        let mut xpriv = seed.master_xpriv(false).expect("invalid seed");
        let mut xpub = ExtendedPubKey::from_priv(secp, &xpriv);

        println!("{}", "Master key:".bright_white());
        println!(
            "{:-18} {}",
            "  - fingerprint:".bright_white(),
            xpub.fingerprint().to_string().bright_green()
        );
        println!("{:-18} {}", "  - id:".bright_white(), xpub.identifier());
        if self.print_private {
            println!(
                "{:-18} {}",
                "  - xprv mainnet:".bright_white(),
                xpriv.to_string().black().dimmed()
            );
            xpriv.network = bitcoin::Network::Testnet;
            println!(
                "{:-18} {}",
                "  - xprv testnet:".bright_white(),
                xpriv.to_string().black().dimmed()
            );
        }
        println!(
            "{:-16} {}",
            " - xprv mainnet:".bright_white(),
            xpriv.to_string().black().dimmed()
        );
        xpriv.network = bitcoin::Network::Testnet;
        println!(
            "{:-16} {}",
            " - xprv testnet:".bright_white(),
            xpriv.to_string().black().dimmed()
        );
        println!(
            "{:-16} {}",
            " - xpub mainnet:".bright_white(),
            xpub.to_string().bright_green()
        );
        xpub.network = bitcoin::Network::Testnet;
        println!(
            "{:-18} {}\n",
            "  - xpub testnet:".bright_white(),
            xpub.to_string().bright_yellow()
        );
    }

    fn info_account(&self, account: MemorySigningAccount) {
        let key_application = KeyApplication::from_derivation_path(account.derivation().clone());
        println!("\n{}", "Account:".bright_white());
        println!(
            "{:-18} {}",
            "  - fingerprint:".bright_white(),
            account.account_fingerprint().to_string().bright_green()
        );
        println!("{:-18} {}", "  - id:".bright_white(), account.account_id());
        println!(
            "{:-18} m=[{}]/{}",
            "  - derivation:".bright_white(),
            account.master_fingerprint(),
            format!("{:#}", account.derivation()).trim_start_matches("m/")
        );
        if self.print_private {
            let account_xpriv = account.account_xpriv();
            println!(
                "{:-18} {}",
                "  - xpriv:".bright_white(),
                account_xpriv.to_string().black().dimmed()
            );
            if let Some(key_application) = key_application {
                println!(
                    "{:-18} {}",
                    "  - slip132 priv:".bright_white(),
                    account_xpriv
                        .to_slip132_string(key_application, account_xpriv.network)
                        .black()
                        .dimmed()
                );
            }
        }
        let account_xpub = account.account_xpub();
        println!(
            "{:-18} {}",
            "  - xpub:".bright_white(),
            account_xpub.to_string().bright_green()
        );
        if let Some(key_application) = key_application {
            println!(
                "{:-18} {}",
                "  - slip132 pub:".bright_white(),
                account_xpub
                    .to_slip132_string(key_application, account_xpub.network)
                    .bright_green()
            );
        }
        if let Some(descriptor) = account.recommended_descriptor() {
            println!(
                "{:-18}\n{}\n",
                "Recommended wallet descriptor:".bright_white(),
                descriptor.to_string().bright_blue()
            );
        } else {
            println!(
                "{:-18}\n{}\n",
                "Recommended use in wallet descriptor:".bright_white(),
                account.to_account().to_string().bright_blue()
            );
        }
    }

    fn info(&self, path: &Path) -> Result<(), Error> {
        let secp = Secp256k1::new();

        let file = fs::File::open(path)?;
        if let Ok(account) = MemorySigningAccount::read(&secp, file) {
            self.info_account(account);
            return Ok(());
        }

        let password = rpassword::read_password_from_tty(Some("Password: "))?;
        if let Ok(seed) = Seed::read(path, &password) {
            self.info_seed(&secp, seed);
            return Ok(());
        }

        eprintln!(
            "{} can't detect file format for `{}`",
            "Error:".bright_red(),
            path.display()
        );

        Ok(())
    }

    fn sign(&self, psbt_path: &Path, account_path: &Path) -> Result<(), Error> {
        let secp = Secp256k1::new();

        let file = fs::File::open(account_path)?;
        let account = MemorySigningAccount::read(&secp, file)?;

        let file = fs::File::open(psbt_path)?;
        let mut psbt = Psbt::strict_decode(&file)?;

        let mut key_provider = MemoryKeyProvider::with(&secp);
        key_provider.add_account(account);

        let sig_count = psbt.sign_all(&key_provider)?;
        println!("Done {} signatures\n", sig_count.to_string().bright_green());

        let file = fs::File::create(psbt_path)?;
        psbt.strict_encode(file)?;

        Ok(())
    }
}

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum Error {
    #[from(io::Error)]
    Io(IoError),

    #[from]
    Bip39(bip39::Error),

    #[from]
    Bip32(bip32::Error),

    #[from]
    Encoding(bitcoin::consensus::encode::Error),

    #[from]
    StrictEncoding(strict_encoding::Error),

    #[from]
    Signing(SignError),
}

fn main() -> Result<(), Error> {
    let args = Args::parse();
    args.exec()
}
