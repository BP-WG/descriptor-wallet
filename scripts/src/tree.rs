// Descriptor wallet library extending bitcoin & miniscript functionality
// by LNP/BP Association (https://lnp-bp.org)
// Written in 2020-2022 by
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

#![allow(missing_docs)]

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::psbt::TapTree;
use bitcoin::util::taproot::{LeafVersion, TapBranchHash, TapLeafHash};
use bitcoin::Script;
use secp256k1::{KeyPair, SECP256K1};
use std::convert::{TryFrom, TryInto};
use std::ops::Deref;

use crate::types::TapNodeHash;
use crate::LeafScript;

/// Ordered set of two branches under taptree node.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct BranchNodes {
    left: Box<TapTreeNode>,
    right: Box<TapTreeNode>,
}

impl BranchNodes {
    pub fn with(a: TapTreeNode, b: TapTreeNode) -> Self {
        let hash1 = a.node_hash();
        let hash2 = b.node_hash();
        if hash1 < hash2 {
            BranchNodes {
                left: Box::new(a),
                right: Box::new(b),
            }
        } else {
            BranchNodes {
                left: Box::new(b),
                right: Box::new(a),
            }
        }
    }

    #[inline]
    pub fn as_left_node(&self) -> &TapTreeNode {
        &self.left
    }

    #[inline]
    pub fn as_right_node(&self) -> &TapTreeNode {
        &self.right
    }

    #[inline]
    pub fn into_left_node(self) -> TapTreeNode {
        *self.left
    }

    #[inline]
    pub fn into_right_node(self) -> TapTreeNode {
        *self.right
    }

    #[inline]
    pub fn split(self) -> (TapTreeNode, TapTreeNode) {
        (*self.left, *self.right)
    }
}

impl BranchNodes {
    pub fn tap_branch_hash(&self) -> TapBranchHash {
        // TODO: Replace with TapBranchHash::from_nodes once #922 will be merged
        let mut engine = TapBranchHash::engine();
        engine.input(&self.as_left_node().node_hash());
        engine.input(&self.as_right_node().node_hash());
        TapBranchHash::from_engine(engine)
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
pub enum TapTreeNode {
    #[from]
    Leaf(LeafScript),
    #[from]
    Hidden(sha256::Hash),
    #[from]
    Branch(BranchNodes),
}

impl TapTreeNode {
    pub fn node_hash(&self) -> sha256::Hash {
        match self {
            TapTreeNode::Leaf(leaf_script) => leaf_script.tap_leaf_hash().into_node_hash(),
            TapTreeNode::Hidden(hash) => *hash,
            TapTreeNode::Branch(branches) => branches.tap_branch_hash().into_node_hash(),
        }
    }
}

impl TryFrom<PartialTreeNode> for TapTreeNode {
    type Error = IncompleteTree;

    fn try_from(partial_node: PartialTreeNode) -> Result<Self, Self::Error> {
        Ok(match partial_node {
            PartialTreeNode::Leaf(leaf_script) => TapTreeNode::Leaf(leaf_script),
            ref node @ PartialTreeNode::Branch(ref branch) => {
                TapTreeNode::Branch(BranchNodes::with(
                    branch
                        .first
                        .as_ref()
                        .ok_or_else(|| IncompleteTree(node.clone()))?
                        .deref()
                        .clone()
                        .try_into()?,
                    branch
                        .second
                        .as_ref()
                        .ok_or_else(|| IncompleteTree(node.clone()))?
                        .deref()
                        .clone()
                        .try_into()?,
                ))
            }
        })
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct TaprootScriptTree {
    root: TapTreeNode,
}

impl TaprootScriptTree {}

/// Taproot script tree is not complete at node {0:?}.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Error, Display)]
#[display(doc_comments)]
pub struct IncompleteTree(PartialTreeNode);

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct PartialBranch {
    pub hash: sha256::Hash,
    pub first: Option<Box<PartialTreeNode>>,
    pub second: Option<Box<PartialTreeNode>>,
}

impl PartialBranch {
    pub fn new(hash: sha256::Hash) -> Self {
        PartialBranch {
            hash,
            first: None,
            second: None,
        }
    }

    pub fn push_child(&mut self, child: PartialTreeNode) -> &mut PartialTreeNode {
        if self
            .first
            .as_ref()
            .map(|c| c.node_hash() == child.node_hash())
            .unwrap_or_default()
        {
            return self.first.as_mut().unwrap();
        }
        if self
            .second
            .as_ref()
            .map(|c| c.node_hash() == child.node_hash())
            .unwrap_or_default()
        {
            return self.second.as_mut().unwrap();
        }
        let child = Box::new(child);
        debug_assert!(self.second.is_none());
        if self.first.is_none() {
            self.first = Some(child);
            self.first.as_mut().unwrap()
        } else {
            self.second = Some(child);
            self.second.as_mut().unwrap()
        }
    }

    #[inline]
    pub fn node_hash(&self) -> sha256::Hash {
        self.hash
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum PartialTreeNode {
    Leaf(LeafScript),
    Branch(PartialBranch),
}

impl PartialTreeNode {
    pub fn leaf(leaf_version: LeafVersion, script: Script) -> PartialTreeNode {
        PartialTreeNode::Leaf(LeafScript::with(leaf_version, script.into()))
    }

    pub fn with_hash(hash: sha256::Hash) -> PartialTreeNode {
        PartialTreeNode::Branch(PartialBranch::new(hash))
    }

    pub fn node_hash(&self) -> sha256::Hash {
        match self {
            PartialTreeNode::Leaf(leaf_script) => leaf_script.tap_leaf_hash().into_node_hash(),
            PartialTreeNode::Branch(branch) => branch.node_hash(),
        }
    }
}

impl From<TapTree> for TaprootScriptTree {
    fn from(tree: TapTree) -> Self {
        // TODO: Do via iterator once #922 will be merged
        let dumb_key = KeyPair::from_secret_key(SECP256K1, secp256k1::ONE_KEY).public_key();
        let spent_info = tree
            .into_inner()
            .finalize(SECP256K1, dumb_key)
            .expect("non-final taptree");

        let mut root: Option<PartialTreeNode> = None;
        for ((script, leaf_version), map) in spent_info.as_script_map() {
            for merkle_branch in map {
                let merkle_branch = merkle_branch.as_inner();

                let mut curr_hash =
                    TapLeafHash::from_script(script, *leaf_version).into_node_hash();
                let merkle_branch = merkle_branch
                    .iter()
                    .map(|step| {
                        // TODO: Repalce with TapBranchHash::from_node_hashes
                        let mut engine = TapBranchHash::engine();
                        if *step < curr_hash {
                            engine.input(step);
                            engine.input(&curr_hash);
                        } else {
                            engine.input(&curr_hash);
                            engine.input(step);
                        }
                        curr_hash = TapBranchHash::from_engine(engine).into_node_hash();
                        curr_hash
                    })
                    .collect::<Vec<_>>();
                let mut hash_iter = merkle_branch.iter().rev();

                match (root.is_some(), hash_iter.next()) {
                    (false, None) => {
                        root = Some(PartialTreeNode::leaf(*leaf_version, script.clone()))
                    }
                    (false, Some(hash)) => root = Some(PartialTreeNode::with_hash(*hash)),
                    (true, None) => unreachable!("broken TapTree structure"),
                    (true, Some(_)) => {}
                }
                let mut node = root.as_mut().expect("unreachable");
                for hash in hash_iter {
                    match node {
                        PartialTreeNode::Leaf(_) => unreachable!("broken TapTree structure"),
                        PartialTreeNode::Branch(branch) => {
                            let child = PartialTreeNode::with_hash(*hash);
                            node = branch.push_child(child);
                        }
                    }
                }
                let leaf = PartialTreeNode::leaf(*leaf_version, script.clone());
                match node {
                    PartialTreeNode::Leaf(_) => unreachable!("broken TapTree structure"),
                    PartialTreeNode::Branch(branch) => {
                        branch.push_child(leaf);
                    }
                }
            }
        }

        let root = root
            .map(TapTreeNode::try_from)
            .transpose()
            .ok()
            .flatten()
            .expect("broken TapTree structure");

        TaprootScriptTree { root }
    }
}

/*
impl Deserialize for TaprootScriptTree {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        let mut vec = vec![];
        let mut bytes_iter = bytes.iter();
        while let Some(depth) = bytes_iter.next() {
            let version = bytes_iter
                .next()
                .ok_or(encode::Error::ParseFailed("invalid taptree data"))?;
            let (script, consumed) = deserialize_partial::<Script>(bytes_iter.as_slice())?;
            if consumed > 0 {
                bytes_iter.nth(consumed - 1);
            }

            let leaf_version = LeafVersion::from_consensus(*version)
                .map_err(|_| encode::Error::ParseFailed("invalid taptree leaf version"))?;
            vec.push((depth, leaf_version, script))
        }
        Ok(vec)
    }
}
*/

#[cfg(test)]
mod test {
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::util::taproot::TaprootBuilder;

    use super::*;

    #[test]
    fn taptree_parsing() {
        let builder = TaprootBuilder::new();
        // Create a tree as shown below
        // For example, imagine this tree:
        // A, B , C are at depth 2 and D,E are at 3
        //                                       ....
        //                                     /      \
        //                                    /\      /\
        //                                   /  \    /  \
        //                                  A    B  C  / \
        //                                            D   E
        let a = Script::from_hex("51").unwrap();
        let b = Script::from_hex("52").unwrap();
        let c = Script::from_hex("53").unwrap();
        let d = Script::from_hex("54").unwrap();
        let e = Script::from_hex("55").unwrap();
        let builder = builder.add_leaf(2, a.clone()).unwrap();
        let builder = builder.add_leaf(2, b.clone()).unwrap();
        let builder = builder.add_leaf(2, c.clone()).unwrap();
        let builder = builder.add_leaf(3, d.clone()).unwrap();
        let builder = builder.add_leaf(3, e.clone()).unwrap();

        let taptree = TapTree::from_inner(builder).unwrap();

        #[allow(unused_variables)]
        let script_tree = TaprootScriptTree::from(taptree);
    }
}
