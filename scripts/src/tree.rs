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

// TODO:
//      1. Add comments (including explanation on non-DFS script iteration).
//      2. Cover edge cases
//      3. Test exact nodes
//      4. Remove hidden nodes

use std::borrow::Borrow;
use std::convert::{TryFrom, TryInto};
use std::ops::Deref;

use amplify::Wrapper;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::psbt::TapTree;
use bitcoin::util::taproot::{LeafVersion, TapBranchHash, TapLeafHash, TaprootBuilder};
use bitcoin::Script;
use secp256k1::{KeyPair, SECP256K1};

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

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct TaprootScriptTree {
    root: TapTreeNode,
}

impl AsRef<TapTreeNode> for TaprootScriptTree {
    fn as_ref(&self) -> &TapTreeNode {
        &self.root
    }
}

impl Borrow<TapTreeNode> for TaprootScriptTree {
    fn borrow(&self) -> &TapTreeNode {
        &self.root
    }
}

impl TaprootScriptTree {
    #[inline]
    pub fn new(tree: TapTree) -> Self {
        TaprootScriptTree::from(tree)
    }

    #[inline]
    pub fn script_iter(&self) -> TreeScriptIter {
        TreeScriptIter::from(self)
    }

    #[inline]
    pub fn dfs_scripts(&self) -> Vec<(u8, &LeafScript)> {
        let mut leafs = self.script_iter().collect::<Vec<_>>();
        leafs.sort_by_key(|(depth, _)| *depth);
        leafs
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
                    PartialTreeNode::Leaf(_) => { /* nothing to do here */ }
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

pub struct TreeScriptIter<'tree> {
    // Here we store vec of path elements, where each element is a tuple, consisting of:
    // 1. Tree node on the path
    // 2. Chirality of the current branch (false - left, true - right)
    // 3. Depth of the current node
    path: Vec<(&'tree TapTreeNode, bool, u8)>,
}

impl<'tree, T> From<&'tree T> for TreeScriptIter<'tree>
where
    T: Borrow<TapTreeNode>,
{
    fn from(tree: &'tree T) -> Self {
        TreeScriptIter {
            path: vec![(tree.borrow(), false, 0)],
        }
    }
}

impl<'tree> Iterator for TreeScriptIter<'tree> {
    type Item = (u8, &'tree LeafScript);

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((node, mut side, mut depth)) = self.path.pop() {
            let mut curr = node;
            loop {
                match curr {
                    // We return only leafs, when found
                    TapTreeNode::Leaf(leaf_script) => {
                        return Some((depth, leaf_script));
                    }
                    // We skip hidden nodes since we can't do anything about them
                    TapTreeNode::Hidden(_) => break,
                    // We restart our search on branching pushing the other
                    // branch to the path
                    TapTreeNode::Branch(branch) if !side => {
                        self.path.push((curr, true, depth));
                        depth += 1;
                        curr = branch.left.as_ref();
                        side = false;
                        continue;
                    }
                    TapTreeNode::Branch(branch) => {
                        depth += 1;
                        curr = branch.right.as_ref();
                        side = false;
                        continue;
                    }
                }
            }
        }
        None
    }
}

impl<'tree> IntoIterator for &'tree TaprootScriptTree {
    type Item = (u8, &'tree LeafScript);
    type IntoIter = TreeScriptIter<'tree>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.script_iter()
    }
}

impl From<&TaprootScriptTree> for TapTree {
    fn from(tree: &TaprootScriptTree) -> Self {
        let mut builder = TaprootBuilder::new();
        for (depth, leaf_script) in tree.dfs_scripts() {
            builder = builder
                .add_leaf_with_ver(
                    depth as usize,
                    leaf_script.script.to_inner(),
                    leaf_script.version,
                )
                .expect("broken TaprootScriptTree");
        }
        TapTree::from_inner(builder).expect("broken TaprootScriptTree")
    }
}

impl From<TaprootScriptTree> for TapTree {
    #[inline]
    fn from(tree: TaprootScriptTree) -> Self {
        TapTree::from(&tree)
    }
}

#[cfg(test)]
mod test {
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::util::taproot::TaprootBuilder;

    use super::*;

    /// Composes tree matching a given depth map, filled with dumb script leafs,
    /// each of which consists of a single push-int op code, with int value
    /// increased for each consecutive leaf.
    fn compose_tree(opcode: u8, depth_map: impl IntoIterator<Item = u8>) -> TapTree {
        let mut val = opcode;
        let mut builder = TaprootBuilder::new();
        for depth in depth_map {
            let script = Script::from_hex(&format!("{:02x}", val)).unwrap();
            builder = builder.add_leaf(depth as usize, script).unwrap();
            let (new_val, _) = val.overflowing_add(1);
            val = new_val;
        }
        TapTree::from_inner(builder).unwrap()
    }

    fn test_tree(opcode: u8, depth_map: impl IntoIterator<Item = u8>) {
        let taptree = compose_tree(opcode, depth_map);
        let script_tree = TaprootScriptTree::from(taptree.clone());

        let _scripts = taptree.iter().collect::<Vec<_>>();
        let _scripts_prime = script_tree
            .dfs_scripts()
            .into_iter()
            .map(|(depth, leaf_script)| (depth, leaf_script.script.as_inner()))
            .collect::<Vec<_>>();
        // TODO: Uncomment assert_eq!(scripts, scripts_prime);

        let taptree_prime = TapTree::from(&script_tree);
        assert_eq!(taptree, taptree_prime);
    }

    fn testsuite_tree_structures(opcode: u8) {
        // Testing all tree variants with up to three levels of depths
        // (up to 8 scripts)
        test_tree(opcode, [0]);
        test_tree(opcode, [1, 1]);
        test_tree(opcode, [1, 2, 2]);
        test_tree(opcode, [2, 2, 2, 2]);
        test_tree(opcode, [1, 2, 3, 3]);
        test_tree(opcode, [1, 3, 3, 3, 3]);
        // Create a tree as shown below
        // A, B , C are at depth 2 and D,E are at 3
        //                                       ....
        //                                     /      \
        //                                    /\      /\
        //                                   /  \    /  \
        //                                  A    B  C  / \
        //                                            D   E
        test_tree(opcode, [2, 2, 2, 3, 3]);
        test_tree(opcode, [2, 2, 3, 3, 3, 3]);
        test_tree(opcode, [2, 3, 3, 3, 3, 3, 3]);
        test_tree(opcode, [3, 3, 3, 3, 3, 3, 3, 3]);
    }

    #[test]
    fn taptree_parsing() {
        // different opcodes may result in different sorting orders, so we try
        // to start with opcodes having different offset
        testsuite_tree_structures(0x51);
        testsuite_tree_structures(51);
        testsuite_tree_structures(0);
        testsuite_tree_structures(0x80);
    }
}
