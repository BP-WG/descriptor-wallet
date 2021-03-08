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

use bitcoin::Script;
use miniscript::{MiniscriptKey, TranslatePk2};

use super::{Category, Error, ScriptConstruction, ScriptSource};
use crate::bip32::{DerivePublicKey, UnhardenedIndex};
use crate::LockScript;

pub trait DeriveLockScript {
    fn derive_lock_script(
        &self,
        child_index: UnhardenedIndex,
        descr_category: Category,
    ) -> Result<LockScript, Error>;
}

impl DeriveLockScript for ScriptSource {
    fn derive_lock_script(
        &self,
        child_index: UnhardenedIndex,
        _: Category,
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
