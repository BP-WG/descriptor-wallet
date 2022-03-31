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

use std::borrow::{Borrow, BorrowMut};
use std::cmp::Ordering;
use std::convert::{TryFrom, TryInto};
use std::fmt::Debug;
use std::ops::Deref;

use amplify::Wrapper;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::psbt::TapTree;
use bitcoin::util::taproot::{LeafVersion, TapBranchHash, TapLeafHash, TaprootBuilder};
use bitcoin::Script;
use secp256k1::{KeyPair, SECP256K1};

use crate::types::TapNodeHash;
use crate::LeafScript;

/// Error indicating that the maximum taproot script tree depth exceeded.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Error, Display)]
#[display("maximum taproot script tree depth exceeded")]
pub struct MaxDepthExceeded;

/// Error indicating that the tree contains just a single known root node and can't
/// be split into two parts.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Error, Display)]
#[display("tree contains just a single known root node and can't be split into two parts.")]
pub struct UnsplittableTree;

/// Error happening when taproot script tree is not complete at certain node.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Error, Display)]
#[display("taproot script tree is not complete at node {0:?}.")]
pub struct IncompleteTreeError<N>(N)
where
    N: Node + Debug;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum DfsOrder {
    First,
    Last,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum DfsOrdering {
    LeftRight,
    RightLeft,
}

pub trait Branch {
    fn subtree_depth(&self) -> Option<u8>;
    fn dfs_ordering(&self) -> DfsOrdering;
    fn branch_hash(&self) -> TapBranchHash;
}

pub trait Node {
    fn is_hidden(&self) -> bool;
    fn is_branch(&self) -> bool;
    fn is_leaf(&self) -> bool;
    fn node_hash(&self) -> sha256::Hash;
    fn node_depth(&self) -> u8;
    fn subtree_depth(&self) -> Option<u8>;
}

/// Ordered set of two branches under taptree node.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct BranchNode {
    left: Box<TreeNode>,
    right: Box<TreeNode>,
    /// The DFS ordering for the branches used in case at least one of the
    /// subnodes is hidden or both branches has the same subtree depth.
    /// Ignored otherwise: a direct measurement of subtree depths is used in this case instead.
    dfs_ordering: DfsOrdering,
}

impl Branch for BranchNode {
    #[inline]
    fn subtree_depth(&self) -> Option<u8> {
        Some(self.left.subtree_depth()?.max(self.right.subtree_depth()?))
    }

    fn dfs_ordering(&self) -> DfsOrdering {
        let left_depth = self.left.subtree_depth();
        let right_depth = self.right.subtree_depth();
        if self.left.is_hidden() || self.right.is_hidden() || left_depth == right_depth {
            self.dfs_ordering
        } else if left_depth < right_depth {
            DfsOrdering::LeftRight
        } else {
            DfsOrdering::RightLeft
        }
    }

    fn branch_hash(&self) -> TapBranchHash {
        // TODO: Replace with TapBranchHash::from_nodes once #922 will be merged
        let mut engine = TapBranchHash::engine();
        engine.input(&self.as_left_node().node_hash());
        engine.input(&self.as_right_node().node_hash());
        TapBranchHash::from_engine(engine)
    }
}

impl BranchNode {
    pub(self) fn with(a: TreeNode, b: TreeNode) -> Self {
        let hash1 = a.node_hash();
        let hash2 = b.node_hash();
        if hash1 < hash2 {
            BranchNode {
                left: Box::new(a),
                right: Box::new(b),
                dfs_ordering: DfsOrdering::LeftRight,
            }
        } else {
            BranchNode {
                left: Box::new(b),
                right: Box::new(a),
                dfs_ordering: DfsOrdering::RightLeft,
            }
        }
    }

    #[inline]
    pub fn split(self) -> (TreeNode, TreeNode) {
        (*self.left, *self.right)
    }

    #[inline]
    pub fn as_left_node(&self) -> &TreeNode {
        &self.left
    }

    #[inline]
    pub fn as_right_node(&self) -> &TreeNode {
        &self.right
    }

    #[inline]
    pub(self) fn as_left_node_mut(&mut self) -> &mut TreeNode {
        &mut self.left
    }

    #[inline]
    pub(self) fn as_right_node_mut(&mut self) -> &mut TreeNode {
        &mut self.right
    }

    #[inline]
    pub fn as_dfs_first_node(&self) -> &TreeNode {
        match self.dfs_ordering() {
            DfsOrdering::LeftRight => self.as_left_node(),
            DfsOrdering::RightLeft => self.as_right_node(),
        }
    }

    #[inline]
    pub fn as_dfs_last_node(&self) -> &TreeNode {
        match self.dfs_ordering() {
            DfsOrdering::LeftRight => self.as_right_node(),
            DfsOrdering::RightLeft => self.as_left_node(),
        }
    }

    #[inline]
    pub(self) fn as_dfs_first_node_mut(&mut self) -> &mut TreeNode {
        match self.dfs_ordering() {
            DfsOrdering::LeftRight => self.as_left_node_mut(),
            DfsOrdering::RightLeft => self.as_right_node_mut(),
        }
    }

    #[inline]
    pub(self) fn as_dfs_last_node_mut(&mut self) -> &mut TreeNode {
        match self.dfs_ordering() {
            DfsOrdering::LeftRight => self.as_right_node_mut(),
            DfsOrdering::RightLeft => self.as_left_node_mut(),
        }
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum TreeNode {
    Leaf(LeafScript, u8),
    Hidden(sha256::Hash, u8),
    Branch(BranchNode, u8),
}

impl TreeNode {
    pub fn with_tap_script(script: Script, depth: u8) -> TreeNode {
        TreeNode::Leaf(
            LeafScript {
                version: LeafVersion::TapScript,
                script: script.into(),
            },
            depth,
        )
    }

    pub fn node_at(&self, path: impl AsRef<[DfsOrder]>) -> Option<&TreeNode> {
        let mut curr = self;
        for step in path.as_ref() {
            let branch = match curr {
                TreeNode::Branch(branch, _) => branch,
                _ => return None,
            };
            curr = match step {
                DfsOrder::First => branch.as_dfs_first_node(),
                DfsOrder::Last => branch.as_dfs_last_node(),
            };
        }
        Some(curr)
    }

    pub(self) fn lower(&mut self) -> Result<u8, MaxDepthExceeded> {
        let old_depth = self.node_depth();
        match self {
            TreeNode::Leaf(_, depth) | TreeNode::Hidden(_, depth) | TreeNode::Branch(_, depth) => {
                *depth = depth.checked_add(1).ok_or(MaxDepthExceeded)?;
            }
        }
        Ok(old_depth)
    }

    pub(self) fn raise(&mut self) -> u8 {
        let old_depth = self.node_depth();
        match self {
            TreeNode::Leaf(_, depth) | TreeNode::Hidden(_, depth) | TreeNode::Branch(_, depth) => {
                *depth -= 1;
            }
        }
        old_depth
    }
}

impl Node for TreeNode {
    fn is_hidden(&self) -> bool {
        matches!(self, TreeNode::Hidden(..))
    }

    fn is_branch(&self) -> bool {
        matches!(self, TreeNode::Branch(..))
    }

    fn is_leaf(&self) -> bool {
        matches!(self, TreeNode::Leaf(..))
    }

    fn node_hash(&self) -> sha256::Hash {
        match self {
            TreeNode::Leaf(leaf_script, _) => leaf_script.tap_leaf_hash().into_node_hash(),
            TreeNode::Hidden(hash, _) => *hash,
            TreeNode::Branch(branches, _) => branches.branch_hash().into_node_hash(),
        }
    }

    fn node_depth(&self) -> u8 {
        match self {
            TreeNode::Leaf(_, depth) | TreeNode::Hidden(_, depth) | TreeNode::Branch(_, depth) => {
                *depth
            }
        }
    }

    fn subtree_depth(&self) -> Option<u8> {
        match self {
            TreeNode::Leaf(_, _) => Some(1),
            TreeNode::Hidden(_, _) => None,
            TreeNode::Branch(branch, _) => Some(branch.subtree_depth()? + 1),
        }
    }
}

impl TryFrom<PartialTreeNode> for TreeNode {
    type Error = IncompleteTreeError<PartialTreeNode>;

    fn try_from(partial_node: PartialTreeNode) -> Result<Self, Self::Error> {
        Ok(match partial_node {
            PartialTreeNode::Leaf(leaf_script, depth) => TreeNode::Leaf(leaf_script, depth),
            ref node @ PartialTreeNode::Branch(ref branch, depth) => TreeNode::Branch(
                BranchNode::with(
                    branch
                        .first
                        .as_ref()
                        .ok_or_else(|| IncompleteTreeError(node.clone()))?
                        .deref()
                        .clone()
                        .try_into()?,
                    branch
                        .second
                        .as_ref()
                        .ok_or_else(|| IncompleteTreeError(node.clone()))?
                        .deref()
                        .clone()
                        .try_into()?,
                ),
                depth,
            ),
        })
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct PartialBranchNode {
    hash: TapBranchHash,
    first: Option<Box<PartialTreeNode>>,
    second: Option<Box<PartialTreeNode>>,
}

impl Branch for PartialBranchNode {
    fn subtree_depth(&self) -> Option<u8> {
        Some(
            self.first
                .as_ref()?
                .subtree_depth()?
                .max(self.second.as_ref()?.subtree_depth()?),
        )
    }

    fn dfs_ordering(&self) -> DfsOrdering {
        match (
            self.first
                .as_ref()
                .map(Box::as_ref)
                .and_then(PartialTreeNode::subtree_depth),
            self.second
                .as_ref()
                .map(Box::as_ref)
                .and_then(PartialTreeNode::subtree_depth),
        ) {
            (Some(first), Some(second)) => match first.cmp(&second) {
                // By default we are always ordered in the same way as children were pushed
                Ordering::Equal => DfsOrdering::LeftRight,
                Ordering::Less => DfsOrdering::LeftRight,
                Ordering::Greater => DfsOrdering::RightLeft,
            },
            // By default we are always ordered in the same way as children were pushed
            _ => DfsOrdering::LeftRight,
        }
    }

    fn branch_hash(&self) -> TapBranchHash {
        self.hash
    }
}

impl PartialBranchNode {
    pub fn with(hash: TapBranchHash) -> Self {
        PartialBranchNode {
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
        sha256::Hash::from_inner(self.hash.into_inner())
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum PartialTreeNode {
    Leaf(LeafScript, u8),
    Branch(PartialBranchNode, u8),
}

impl PartialTreeNode {
    pub fn with_leaf(leaf_version: LeafVersion, script: Script, depth: u8) -> PartialTreeNode {
        PartialTreeNode::Leaf(LeafScript::with(leaf_version, script.into()), depth)
    }

    pub fn with_branch(hash: TapBranchHash, depth: u8) -> PartialTreeNode {
        PartialTreeNode::Branch(PartialBranchNode::with(hash), depth)
    }
}

impl Node for PartialTreeNode {
    #[inline]
    fn is_hidden(&self) -> bool {
        false
    }

    fn is_branch(&self) -> bool {
        matches!(self, PartialTreeNode::Branch(..))
    }

    fn is_leaf(&self) -> bool {
        matches!(self, PartialTreeNode::Leaf(..))
    }

    fn node_hash(&self) -> sha256::Hash {
        match self {
            PartialTreeNode::Leaf(leaf_script, _) => leaf_script.tap_leaf_hash().into_node_hash(),
            PartialTreeNode::Branch(branch, _) => branch.node_hash(),
        }
    }

    fn node_depth(&self) -> u8 {
        match self {
            PartialTreeNode::Leaf(_, depth) | PartialTreeNode::Branch(_, depth) => *depth,
        }
    }

    fn subtree_depth(&self) -> Option<u8> {
        match self {
            PartialTreeNode::Leaf(_, _) => Some(0),
            PartialTreeNode::Branch(branch, _) => branch.subtree_depth(),
        }
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct TaprootScriptTree {
    root: TreeNode,
}

impl AsRef<TreeNode> for TaprootScriptTree {
    fn as_ref(&self) -> &TreeNode {
        &self.root
    }
}

impl Borrow<TreeNode> for TaprootScriptTree {
    fn borrow(&self) -> &TreeNode {
        &self.root
    }
}

impl BorrowMut<TreeNode> for TaprootScriptTree {
    fn borrow_mut(&mut self) -> &mut TreeNode {
        &mut self.root
    }
}

impl TaprootScriptTree {
    #[inline]
    pub fn scripts(&self) -> TreeScriptIter {
        TreeScriptIter::from(self)
    }

    #[inline]
    pub fn nodes(&self) -> TreeNodeIter {
        TreeNodeIter::from(self)
    }

    #[inline]
    pub(self) fn nodes_mut(&mut self) -> TreeNodeIterMut {
        TreeNodeIterMut::from(self)
    }

    #[inline]
    pub fn node_at(&self, path: impl AsRef<[DfsOrder]>) -> Option<&TreeNode> {
        self.root.node_at(path)
    }

    /// Joins two trees together under a new root.
    pub fn join(
        mut self,
        mut other_tree: TaprootScriptTree,
        dfs_ordering: DfsOrdering,
    ) -> Result<TaprootScriptTree, MaxDepthExceeded> {
        for n in self.nodes_mut() {
            n.lower()?;
        }
        for n in other_tree.nodes_mut() {
            n.lower()?;
        }
        let instill = other_tree.into_root_node();
        let base = self.into_root_node();
        let branch = if dfs_ordering == DfsOrdering::LeftRight {
            BranchNode::with(instill, base)
        } else {
            BranchNode::with(base, instill)
        };
        Ok(TaprootScriptTree {
            root: TreeNode::Branch(branch, 0),
        })
    }

    /// Splits the tree into two subtrees. Errors if the tree root is hidden or
    /// a script leaf.
    ///
    /// The trees are returned in the original DFS ordering.
    pub fn split(self) -> Result<(TaprootScriptTree, TaprootScriptTree), UnsplittableTree> {
        let (mut first, mut last) = match self.into_root_node() {
            TreeNode::Leaf(_, _) | TreeNode::Hidden(_, _) => return Err(UnsplittableTree),
            TreeNode::Branch(branch, _) if branch.dfs_ordering == DfsOrdering::LeftRight => {
                branch.split()
            }
            TreeNode::Branch(branch, _) => {
                let (left, right) = branch.split();
                (right, left)
            }
        };

        first.raise();
        last.raise();

        Ok((
            TaprootScriptTree { root: first },
            TaprootScriptTree { root: last },
        ))
    }

    #[inline]
    pub fn as_root_node(&self) -> &TreeNode {
        &self.root
    }

    #[inline]
    pub fn into_root_node(self) -> TreeNode {
        self.root
    }

    #[inline]
    pub fn to_root_node(&self) -> TreeNode {
        self.root.clone()
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
                let leaf_depth = merkle_branch.len() as u8;

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
                        root = Some(PartialTreeNode::with_leaf(*leaf_version, script.clone(), 0))
                    }
                    (false, Some(hash)) => {
                        root = Some(PartialTreeNode::with_branch(
                            TapBranchHash::from_inner(hash.into_inner()),
                            0,
                        ))
                    }
                    (true, None) => unreachable!("broken TapTree structure"),
                    (true, Some(_)) => {}
                }
                let mut node = root.as_mut().expect("unreachable");
                for (depth, hash) in hash_iter.enumerate() {
                    match node {
                        PartialTreeNode::Leaf(..) => unreachable!("broken TapTree structure"),
                        PartialTreeNode::Branch(branch, _) => {
                            let child = PartialTreeNode::with_branch(
                                TapBranchHash::from_inner(hash.into_inner()),
                                depth as u8 + 1,
                            );
                            node = branch.push_child(child);
                        }
                    }
                }
                let leaf = PartialTreeNode::with_leaf(*leaf_version, script.clone(), leaf_depth);
                match node {
                    PartialTreeNode::Leaf(..) => { /* nothing to do here */ }
                    PartialTreeNode::Branch(branch, _) => {
                        branch.push_child(leaf);
                    }
                }
            }
        }

        let root = root
            .map(TreeNode::try_from)
            .transpose()
            .ok()
            .flatten()
            .expect("broken TapTree structure");

        TaprootScriptTree { root }
    }
}

pub struct TreeNodeIter<'tree> {
    stack: Vec<&'tree TreeNode>,
}

impl<'tree, T> From<&'tree T> for TreeNodeIter<'tree>
where
    T: Borrow<TreeNode>,
{
    fn from(tree: &'tree T) -> Self {
        TreeNodeIter {
            stack: vec![tree.borrow()],
        }
    }
}

impl<'tree> Iterator for TreeNodeIter<'tree> {
    type Item = &'tree TreeNode;

    fn next(&mut self) -> Option<Self::Item> {
        let curr = self.stack.pop()?;
        match curr {
            TreeNode::Branch(branch, _) => {
                self.stack.push(branch.as_dfs_first_node());
                self.stack.push(branch.as_dfs_last_node());
            }
            _ => { /* do nothing */ }
        }
        return Some(curr);
    }
}

struct TreeNodeIterMut<'tree> {
    root: &'tree mut TreeNode,
    stack: Vec<Vec<DfsOrder>>,
}

impl<'tree, T> From<&'tree mut T> for TreeNodeIterMut<'tree>
where
    T: BorrowMut<TreeNode>,
{
    fn from(tree: &'tree mut T) -> Self {
        TreeNodeIterMut {
            root: tree.borrow_mut(),
            stack: vec![vec![]],
        }
    }
}

impl<'tree> Iterator for TreeNodeIterMut<'tree> {
    type Item = &'tree mut TreeNode;

    fn next(&mut self) -> Option<Self::Item> {
        let mut path = self.stack.pop()?;

        // We need this because of rust compiler not accepting the fact that
        // the root is a part of the self, and that 'tree lifetime will never
        // outlive the lifetime of the self.
        let mut curr = unsafe { &mut *(self.root as *mut TreeNode) as &'tree mut TreeNode };
        for step in &path {
            let branch = match curr {
                TreeNode::Branch(branch, _) => branch,
                _ => unreachable!("iteration algorithm is broken"),
            };
            curr = match step {
                DfsOrder::First => branch.as_dfs_first_node_mut(),
                DfsOrder::Last => branch.as_dfs_last_node_mut(),
            };
        }

        if curr.is_branch() {
            path.push(DfsOrder::First);
            self.stack.push(path.clone());
            path.pop();
            path.push(DfsOrder::Last);
            self.stack.push(path);
        }
        return Some(curr);
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
enum BranchDirection {
    Shallow,
    Deep,
}

pub struct TreeScriptIter<'tree> {
    // Here we store vec of path elements, where each element is a tuple, consisting of:
    // 1. Tree node on the path
    // 2. Selection of the current branch (false - shallow, true - deep)
    path: Vec<(&'tree TreeNode, BranchDirection)>,
}

impl<'tree, T> From<&'tree T> for TreeScriptIter<'tree>
where
    T: Borrow<TreeNode>,
{
    fn from(tree: &'tree T) -> Self {
        TreeScriptIter {
            path: vec![(tree.borrow(), BranchDirection::Shallow)],
        }
    }
}

impl<'tree> Iterator for TreeScriptIter<'tree> {
    type Item = (u8, &'tree LeafScript);

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((node, mut side)) = self.path.pop() {
            let mut curr = node;
            loop {
                match curr {
                    // We return only leafs, when found
                    TreeNode::Leaf(leaf_script, depth) => {
                        return Some((*depth, leaf_script));
                    }
                    // We skip hidden nodes since we can't do anything about them
                    TreeNode::Hidden(..) => break,
                    // We restart our search on branching pushing the other
                    // branch to the path
                    TreeNode::Branch(branch, _) if side == BranchDirection::Shallow => {
                        self.path.push((curr, BranchDirection::Deep));
                        curr = branch.as_dfs_first_node();
                        side = BranchDirection::Shallow;
                        continue;
                    }
                    TreeNode::Branch(branch, _) => {
                        curr = branch.as_dfs_last_node();
                        side = BranchDirection::Shallow;
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
        self.scripts()
    }
}

impl From<&TaprootScriptTree> for TapTree {
    fn from(tree: &TaprootScriptTree) -> Self {
        let mut builder = TaprootBuilder::new();
        for (depth, leaf_script) in tree.scripts() {
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
    use bitcoin::blockdata::opcodes::all;
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::util::taproot::TaprootBuilder;
    use std::collections::BTreeSet;

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

        let scripts = taptree.iter().collect::<BTreeSet<_>>();
        let scripts_prime = script_tree
            .scripts()
            .map(|(depth, leaf_script)| (depth, leaf_script.script.as_inner()))
            .collect::<BTreeSet<_>>();
        assert_eq!(scripts, scripts_prime);

        let taptree_prime = TapTree::from(&script_tree);
        assert_eq!(taptree, taptree_prime);
    }

    fn test_instill(depth_map: impl IntoIterator<Item = u8>) {
        let taptree = compose_tree(0x51, depth_map);
        let script_tree = TaprootScriptTree::from(taptree.clone());

        let instill_tree = compose_tree(all::OP_RETURN.into_u8(), [0]).into();
        let merged_tree = script_tree
            .clone()
            .join(instill_tree, DfsOrdering::LeftRight)
            .unwrap();

        let _ = TapTree::from(&merged_tree);
        assert_ne!(merged_tree, script_tree);

        let order = match merged_tree.root {
            TreeNode::Branch(ref branch, 0) => branch.dfs_ordering,
            _ => panic!("instill algorithm is broken"),
        };

        match (
            merged_tree.node_at([DfsOrder::First]).unwrap(),
            merged_tree.node_at([DfsOrder::Last]).unwrap(),
            order,
        ) {
            (TreeNode::Leaf(leaf_script, 1), _, DfsOrdering::LeftRight)
            | (TreeNode::Leaf(leaf_script, 1), _, DfsOrdering::RightLeft)
                if leaf_script.script[0] == all::OP_RETURN.into_u8() =>
            {
                // Everything is fine
            }
            (_, TreeNode::Leaf(leaf_script, 1), ordering)
                if leaf_script.script[0] == all::OP_RETURN.into_u8() =>
            {
                panic!(
                    "instilled tree with script `{:?}` has incorrect DFS ordering {:?}",
                    leaf_script.script, ordering
                )
            }
            (TreeNode::Leaf(_, x), _, _) => {
                panic!("broken mergged tree depth of first branches: {}", x);
            }
            _ => panic!("instilled tree is not present as first branch of the merged tree"),
        }
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

    #[test]
    fn taptree_instill() {
        test_instill([0]);
        test_instill([1, 1]);
        test_instill([1, 2, 2]);
        test_instill([2, 2, 2, 2]);
        test_instill([1, 2, 3, 3]);
        test_instill([1, 3, 3, 3, 3]);
        test_instill([2, 2, 2, 3, 3]);
        test_instill([2, 2, 3, 3, 3, 3]);
        test_instill([2, 3, 3, 3, 3, 3, 3]);
        test_instill([3, 3, 3, 3, 3, 3, 3, 3]);
    }
}
