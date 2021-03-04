// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use bitcoin::Script;
use miniscript::{MiniscriptKey, TranslatePk2};

use super::{Error, ScriptConstruction, ScriptSource, SubCategory};
use crate::bip32::{DerivePublicKey, UnhardenedIndex};
use crate::LockScript;

pub trait DeriveLockScript {
    fn derive_lock_script(
        &self,
        child_index: UnhardenedIndex,
        descr_category: SubCategory,
    ) -> Result<LockScript, Error>;
}

impl DeriveLockScript for ScriptSource {
    fn derive_lock_script(
        &self,
        child_index: UnhardenedIndex,
        _: SubCategory,
    ) -> Result<LockScript, Error> {
        let ms = match &self.script {
            ScriptConstruction::Miniscript(ms) => ms.clone(),
            ScriptConstruction::MiniscriptPolicy(policy) => policy.compile()?,
            ScriptConstruction::ScriptTemplate(template) => {
                return Ok(
                    Script::from(template.translate_pk(child_index)).into()
                )
            }
        };

        let ms = ms.translate_pk2(|pk| {
            if pk.is_uncompressed() {
                return Err(Error::UncompressedKeyInSegWitContext);
            }
            Ok(pk.derive_public_key(child_index))
        })?;
        Ok(ms.encode().into())
    }
}
