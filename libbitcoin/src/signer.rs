// C library for building descriptor-based bitcoin wallets
//
// Written in 2021 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the Apache 2.0 License
// along with this software.
// If not, see <https://opensource.org/licenses/Apache-2.0>.

use libc::c_char;
use std::ffi::{CStr, CString};
use std::ops::{ControlFlow, Try};
use std::slice;
use std::str::{FromStr, Utf8Error};

use bip39::Mnemonic;
use bitcoin::util::bip32::{
    self, DerivationPath, Error, ExtendedPrivKey, ExtendedPubKey,
};
use bitcoin::Network;
use rand::RngCore;

use crate::helpers::Wipe;

lazy_static! {
    /// Global Secp256k1 context object
    pub static ref SECP256K1: bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All> =
        bitcoin::secp256k1::Secp256k1::new();
}

#[derive(
    Clone,
    Copy,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    Display,
    Error,
    From,
)]
#[allow(non_camel_case_types)]
#[repr(u16)]
#[display(doc_comments)]
pub enum error_t {
    #[display("")]
    success = 0,

    /// got a null pointer as one of the function arguments
    null_pointer,

    /// result data must be a valid string which does not contain zero bytes
    invalid_result_data,

    /// invalid mnemonic string
    #[from(bip39::Error)]
    invalid_mnemonic,

    /// invalid UTF-8 string
    #[from(Utf8Error)]
    invalid_utf8_string,

    /// wrong BIP32 extended public or private key data
    wrong_extended_key,

    /// unable to derive hardened path from a public key
    unable_to_derive_hardened,

    /// invalid derivation path
    invalid_derivation_path,

    /// general BIP32-specific failure
    bip32_failure,
}

impl Default for error_t {
    fn default() -> Self {
        error_t::success
    }
}

impl From<bip32::Error> for error_t {
    fn from(err: bip32::Error) -> Self {
        match err {
            Error::CannotDeriveFromHardenedKey => {
                error_t::unable_to_derive_hardened
            }

            Error::InvalidChildNumber(_)
            | Error::InvalidChildNumberFormat
            | Error::InvalidDerivationPathFormat => {
                error_t::invalid_derivation_path
            }

            Error::Base58(_)
            | Error::UnknownVersion(_)
            | Error::WrongExtendedKeyLength(_) => error_t::wrong_extended_key,

            Error::RngError(_) | Error::Ecdsa(_) => error_t::bip32_failure,
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct string_result_t {
    pub code: error_t,
    pub details: result_details_t,
}

impl string_result_t {
    pub fn success(data: impl ToString) -> string_result_t {
        let (code, details) = match CString::new(data.to_string()) {
            Ok(s) => {
                (error_t::success, result_details_t { data: s.into_raw() })
            }
            Err(err) => (error_t::invalid_result_data, err.into()),
        };
        string_result_t { code, details }
    }

    pub fn error(code: error_t) -> string_result_t {
        string_result_t {
            code,
            details: result_details_t {
                data: CString::new(code.to_string())
                    .expect("Null byte in error_t code doc comments")
                    .into_raw(),
            },
        }
    }

    pub fn is_success(&self) -> bool {
        self.code == error_t::success
    }
}

impl Try for string_result_t {
    type Ok = result_details_t;
    type Error = error_t;

    fn into_result(self) -> Result<Self::Ok, Self::Error> {
        if self.is_success() {
            Ok(self.details)
        } else {
            Err(self.code)
        }
    }

    fn from_error(v: Self::Error) -> Self {
        v.into()
    }

    fn from_ok(v: Self::Ok) -> Self {
        string_result_t {
            code: error_t::success,
            details: v,
        }
    }
}

impl<E> From<E> for string_result_t
where
    E: std::error::Error + Clone + Into<error_t>,
{
    fn from(err: E) -> Self {
        string_result_t {
            code: err.clone().into(),
            details: result_details_t::from(err),
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub union result_details_t {
    pub data: *const c_char,
    pub error: *const c_char,
}

impl<E> From<E> for result_details_t
where
    E: std::error::Error,
{
    fn from(err: E) -> Self {
        result_details_t {
            error: CString::new(err.to_string())
                .unwrap_or(
                    CString::new("no string error representation").unwrap(),
                )
                .into_raw(),
        }
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[allow(non_camel_case_types)]
#[repr(u16)]
pub enum bip39_mnemonic_type {
    words_12,
    words_15,
    words_18,
    words_21,
    words_24,
}

impl bip39_mnemonic_type {
    pub fn byte_len(self) -> usize {
        match self {
            bip39_mnemonic_type::words_12 => 16,
            bip39_mnemonic_type::words_15 => 160 / 8,
            bip39_mnemonic_type::words_18 => 192 / 8,
            bip39_mnemonic_type::words_21 => 224 / 8,
            bip39_mnemonic_type::words_24 => 32,
        }
    }

    pub fn word_len(self) -> usize {
        (self.byte_len() * 8 + self.byte_len() * 8 / 32) / 11
    }
}

#[no_mangle]
pub unsafe extern "C" fn result_destroy(result: string_result_t) {
    let ptr = result.details.data;
    if ptr.is_null() {
        return;
    }
    let cs = CString::from_raw(ptr as *mut c_char);
    cs.wipe();
}

/// Creates a rust-owned mnemonic string. You MUSt always call
/// [`string_destroy`] right after storing the mnemonic string and
/// do not call other methods from this library on that mnemonic. If you need
/// to call [`bip39_master_xpriv`] you MUST read mnemonic again and provide
/// unowned string to the rust.
#[no_mangle]
pub extern "C" fn bip39_mnemonic_create(
    entropy: *const u8,
    mnemonic_type: bip39_mnemonic_type,
) -> string_result_t {
    let entropy = if entropy.is_null() {
        let mut inner = Vec::with_capacity(mnemonic_type.byte_len());
        rand::thread_rng().fill_bytes(&mut inner);
        inner
    } else {
        unsafe { slice::from_raw_parts(entropy, mnemonic_type.byte_len()) }
            .to_vec()
    };
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy)?;
    string_result_t::success(mnemonic)
}

#[no_mangle]
pub extern "C" fn bip39_master_xpriv(
    seed_phrase: *mut c_char,
    passwd: *mut c_char,
    wipe: bool,
    testnet: bool,
) -> string_result_t {
    if seed_phrase.is_null() {
        Err(error_t::null_pointer)?
    }

    let password = if passwd.is_null() {
        ""
    } else {
        unsafe { CStr::from_ptr(passwd).to_str()? }
    };

    let mut seed = {
        let seed_phrase = unsafe { CString::from_raw(seed_phrase) };
        let mnemonic = Mnemonic::from_str(seed_phrase.to_str()?)?;
        let seed = mnemonic.to_seed(password);
        if wipe {
            unsafe { seed_phrase.wipe() };
            let s = mnemonic.to_string();
            let len = s.len();
            let ptr = s.as_ptr() as *mut c_char;
            for i in 0..len as isize {
                unsafe { *ptr.offset(i) = 0 };
            }
        }
        seed
    };
    let mut xpriv = ExtendedPrivKey::new_master(
        if testnet {
            Network::Testnet
        } else {
            Network::Bitcoin
        },
        &seed,
    )?;
    seed.fill(0u8);
    if wipe && !passwd.is_null() {
        let len = password.len();
        for i in 0..len as isize {
            unsafe { *passwd.offset(i) = 0 };
        }
    }
    let xpriv_str = xpriv.to_string();
    let ptr = xpriv.private_key.key.as_mut_ptr();
    for i in 0..32 {
        unsafe {
            *ptr.offset(i) = 0;
        }
    }
    string_result_t::success(&xpriv_str)
}

#[no_mangle]
pub extern "C" fn bip32_derive_xpriv(
    master: *mut c_char,
    wipe: bool,
    derivation: *const c_char,
) -> string_result_t {
    let master_cstring = unsafe { CString::from_raw(master) };
    let mut master = ExtendedPrivKey::from_str(master_cstring.to_str()?)?;

    let derivation = unsafe { CStr::from_ptr(derivation).to_str()? };
    let derivation = DerivationPath::from_str(derivation)?;

    let mut xpriv = master.derive_priv(&SECP256K1, &derivation)?;

    if wipe {
        unsafe { master_cstring.wipe() };
    }

    let xpriv_str = xpriv.to_string();
    let ptr1 = master.private_key.key.as_mut_ptr();
    let ptr2 = xpriv.private_key.key.as_mut_ptr();
    for i in 0..32 {
        unsafe {
            *ptr1.offset(i) = 0;
            *ptr2.offset(i) = 0;
        }
    }
    string_result_t::success(&xpriv_str)
}

#[no_mangle]
pub extern "C" fn bip32_derive_xpub(
    master: *mut c_char,
    wipe: bool,
    derivation: *const c_char,
) -> string_result_t {
    let master_cstring = unsafe { CString::from_raw(master) };

    let derivation = unsafe { CStr::from_ptr(derivation).to_str()? };
    let derivation = DerivationPath::from_str(derivation)?;

    if let Ok(mut master) = ExtendedPrivKey::from_str(master_cstring.to_str()?)
    {
        let mut xpriv = master.derive_priv(&SECP256K1, &derivation)?;
        if wipe {
            unsafe { master_cstring.wipe() };
        }

        let xpub = ExtendedPubKey::from_private(&SECP256K1, &xpriv);

        let ptr1 = master.private_key.key.as_mut_ptr();
        let ptr2 = xpriv.private_key.key.as_mut_ptr();
        for i in 0..32 {
            unsafe {
                *ptr1.offset(i) = 0;
                *ptr2.offset(i) = 0;
            }
        }
        string_result_t::success(&xpub)
    } else {
        let master = ExtendedPubKey::from_str(master_cstring.to_str()?)?;
        let xpub = master.derive_pub(&SECP256K1, &derivation)?;
        string_result_t::success(&xpub)
    }
}

#[no_mangle]
pub extern "C" fn psbt_sign(
    _psbt: *const c_char,
    _xpriv: *const c_char,
    _wipe: bool,
) -> string_result_t {
    unimplemented!()
}
