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
use std::ffi::CString;

pub trait Wipe {
    unsafe fn wipe(self);
}

impl Wipe for CString {
    unsafe fn wipe(self) {
        let len = self.as_bytes().len();
        let ptr = self.as_ptr() as *mut c_char;
        for i in 0..len as isize {
            *ptr.offset(i) = 0;
        }
        std::mem::drop(self);
    }
}
