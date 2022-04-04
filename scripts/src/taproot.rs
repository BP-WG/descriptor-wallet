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

//! Taproot script tree implementation allowing arbitrary tree processing/
//! modification (see [`TaprootScriptTree`] structure).

use std::borrow::{Borrow, BorrowMut};
use std::cmp::Ordering;
use std::convert::{TryFrom, TryInto};
use std::fmt::{self, Debug, Display, Formatter};
use std::iter::FromIterator;
use std::ops::{Deref, Not};
use std::str::FromStr;

use amplify::Wrapper;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::psbt::TapTree;
use bitcoin::util::taproot::{LeafVersion, TapBranchHash, TapLeafHash, TaprootBuilder};
use bitcoin::Script;
use secp256k1::{KeyPair, SECP256K1};

use crate::types::IntoNodeHash;
use crate::{LeafScript, TapNodeHash};

/// Error indicating that the maximum taproot script tree depth exceeded.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Error, Display)]
#[display("maximum taproot script tree depth exceeded.")]
pub struct MaxDepthExceeded;

/// Error indicating an attempt to raise subtree above its depth (i.e. root).
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Error, Display)]
#[display("an attempt to raise subtree above its depth.")]
pub struct RaiseAboveRoot;

/// Error indicating that the tree contains just a single known root node and
/// can't be split into two parts.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Error, Display)]
#[display("tree contains just a single known root node and can't be split into two parts.")]
pub struct UnsplittableTree;

/// Error happening when taproot script tree is not complete at certain node.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Error, Display)]
#[display("taproot script tree is not complete at node {0:?}.")]
pub struct IncompleteTreeError<N>(N)
where
    N: Node + Debug;

/// Errors happening during tree instill operation (see
/// [`TaprootScriptTree::instill`]).
#[derive(
    Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Debug, Display, Error, From
)]
#[display(doc_comments)]
pub enum InstillError {
    /// unable to instill subtree into taproot script tree since the depth of
    /// the resulting tree exceeds taproot limit.
    #[from(MaxDepthExceeded)]
    MaxDepthExceeded,

    /// unable to instill subtree into taproot script tree since {0}
    #[from]
    DfsTraversal(DfsTraversalError),
}

/// Errors happening during tree cut operation (see [`TaprootScriptTree::cut`]).
#[derive(
    Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Debug, Display, Error, From
)]
#[display(doc_comments)]
pub enum CutError {
    /// unable to instill subtree into taproot script tree since the cut point
    /// contains leaf or hidden node and thus can't be split into two subtrees.
    #[from(UnsplittableTree)]
    UnsplittableTree,

    /// unable to cut subtree from taproot script tree since {0}
    #[from]
    DfsTraversal(DfsTraversalError),
}

/// Error happening when a provided DFS path does not exist within a known part
/// of a tree.
#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum DfsTraversalError {
    /// the provided DFS path {0} does not exist within a given tree.
    PathNotExists(DfsPath),

    /// the provided DFS path traverses hidden node {node_hash} at
    /// {failed_path} to {path_leftover}.
    HiddenNode {
        /// The hash of the hidden node found during the path traversal.
        node_hash: TapNodeHash,
        /// The path segment which leads to the hidden node.
        failed_path: DfsPath,
        /// The path segment which was not able to traverse after the hidden
        /// node.
        path_leftover: DfsPath,
    },

    /// the provided DFS path traverses leaf node {leaf_script} at
    /// {failed_path} to {path_leftover}.
    LeafNode {
        /// The hash of the leaf script of a leaf node found during the path
        /// traversal.
        leaf_script: LeafScript,
        /// The path segment which leads to the leaf node.
        failed_path: DfsPath,
        /// The path segment which was not able to traverse after the leaf node.
        path_leftover: DfsPath,
    },
}

/// Represents position of a child node under some parent in DFS (deep first
/// search) order.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum DfsOrder {
    /// The child node is the first one, in terms of DFS ordering.
    #[display("dfs-first")]
    First,

    /// The child node is the last one (i.e. the second one), in terms of DFS
    /// ordering.
    #[display("dfs-last")]
    Last,
}

impl Not for DfsOrder {
    type Output = DfsOrder;

    fn not(self) -> Self::Output {
        match self {
            DfsOrder::First => DfsOrder::Last,
            DfsOrder::Last => DfsOrder::First,
        }
    }
}

/// Keeps information about DFS ordering of the child nodes under some parent
/// node. Used in situations when the node organizes child elements basing on
/// the lexicographic ordering of the node hashes; but still need to keep
/// the information about an original DFS ordering.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum DfsOrdering {
    /// The first child under a current ordering is also the first child under
    /// DFS ordering.
    #[display("left-to-right")]
    LeftRight,

    /// The first child under a current ordering is the last child unnder
    /// DFS ordering.
    #[display("right-to-left")]
    RightLeft,
}

impl Not for DfsOrdering {
    type Output = DfsOrdering;

    fn not(self) -> Self::Output {
        match self {
            DfsOrdering::LeftRight => DfsOrdering::RightLeft,
            DfsOrdering::RightLeft => DfsOrdering::LeftRight,
        }
    }
}

/// DFS path within the tree.
///
/// A wrapper type around vector of [`DfsOrder`] items for simple display
/// operations.
#[derive(
    Wrapper, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug, From
)]
pub struct DfsPath(Vec<DfsOrder>);

impl AsRef<[DfsOrder]> for DfsPath {
    #[inline]
    fn as_ref(&self) -> &[DfsOrder] { self.0.as_ref() }
}

impl Display for DfsPath {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for step in self {
            f.write_str(match step {
                DfsOrder::First => "0",
                DfsOrder::Last => "1",
            })?;
        }
        Ok(())
    }
}

/// Error parsing string DFS path representation.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display("the given DFS path {0} can't be parsed: an unexpected character {1} was found.")]
pub struct DfsPathParseError(pub String, pub char);

impl FromStr for DfsPath {
    type Err = DfsPathParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.chars()
            .map(|c| match c {
                '0' => Ok(DfsOrder::First),
                '1' => Ok(DfsOrder::Last),
                other => Err(DfsPathParseError(s.to_string(), other)),
            })
            .collect()
    }
}

impl DfsPath {
    /// Initializes a new empty path instance.
    #[inline]
    pub fn new() -> DfsPath { DfsPath(vec![]) }

    /// Constructs DFS path from an iterator over path steps.
    pub fn with<'path>(iter: impl IntoIterator<Item = &'path DfsOrder>) -> Self {
        DfsPath::from_iter(iter)
    }
}

impl<'path> IntoIterator for &'path DfsPath {
    type Item = DfsOrder;
    type IntoIter = core::iter::Cloned<core::slice::Iter<'path, DfsOrder>>;

    fn into_iter(self) -> Self::IntoIter { self.0.iter().cloned() }
}

impl IntoIterator for DfsPath {
    type Item = DfsOrder;
    type IntoIter = std::vec::IntoIter<DfsOrder>;

    fn into_iter(self) -> Self::IntoIter { self.0.into_iter() }
}

impl FromIterator<DfsOrder> for DfsPath {
    fn from_iter<T: IntoIterator<Item = DfsOrder>>(iter: T) -> Self {
        Self::from_inner(iter.into_iter().collect())
    }
}

impl<'iter> FromIterator<&'iter DfsOrder> for DfsPath {
    fn from_iter<T: IntoIterator<Item = &'iter DfsOrder>>(iter: T) -> Self {
        Self::from_inner(iter.into_iter().copied().collect())
    }
}

/// Trait for taproot tree branch types.
///
/// Tree branch is a set of two child nodes.
pub trait Branch {
    /// Returns the depth of the subtree under this branch node, if the subtree
    /// is fully known (i.e. does not contain hidden nodes), or `None`
    /// otherwise. The depth of subtree for leaf nodes is zero.
    fn subtree_depth(&self) -> Option<u8>;
    /// Returns correspondence between internal child node ordering and their
    /// DFS ordering.
    fn dfs_ordering(&self) -> DfsOrdering;
    /// Computes branch hash of this branch node.
    fn branch_hash(&self) -> TapBranchHash;
}

/// Trait for taproot tree node types.
///
/// Tree node is either a script leaf node, tree branch node or a hidden node.
pub trait Node {
    /// Detects if the node is hidden node, represented just by a hash value.
    /// It can't be known whether hidden node is a leaf node or a branch node.
    fn is_hidden(&self) -> bool;
    /// Detects if the node is branch node (i.e. a node with two child nodes).
    fn is_branch(&self) -> bool;
    /// Detects if the node is a script leaf node.
    fn is_leaf(&self) -> bool;
    /// Computes universal node hash.
    fn node_hash(&self) -> TapNodeHash;
    /// Returns the depth of this node within the tree.
    fn node_depth(&self) -> u8;
    /// Returns the depth of the subtree under this node, if the subtree is
    /// fully known (i.e. does not contain hidden nodes), or `None` otherwise.
    /// The depth of subtree for leaf nodes is zero.
    fn subtree_depth(&self) -> Option<u8>;
}

/// Ordered set of two branches under taptree node.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct BranchNode {
    /// The left (in bitcoin consensus lexicographic ordering) child node.
    left: Box<TreeNode>,
    /// The right (in bitcoin consensus lexicographic ordering) child node.
    right: Box<TreeNode>,
    /// The DFS ordering for the branches used in case at least one of the
    /// child nodes is hidden or both branches has the same subtree depth.
    /// Ignored otherwise: a direct measurement of subtree depths is used in
    /// this case instead.
    dfs_ordering: DfsOrdering,
}

impl Branch for BranchNode {
    #[inline]
    fn subtree_depth(&self) -> Option<u8> {
        Some(self.left.subtree_depth()?.max(self.right.subtree_depth()?))
    }

    fn dfs_ordering(&self) -> DfsOrdering { self.dfs_ordering }

    fn branch_hash(&self) -> TapBranchHash {
        // TODO: Replace with TapBranchHash::from_nodes once #922 will be merged
        let mut engine = TapBranchHash::engine();
        engine.input(&self.as_left_node().node_hash());
        engine.input(&self.as_right_node().node_hash());
        TapBranchHash::from_engine(engine)
    }
}

impl BranchNode {
    pub(self) fn with(first: TreeNode, last: TreeNode) -> Self {
        let hash1 = first.node_hash();
        let hash2 = last.node_hash();
        if hash1 < hash2 {
            BranchNode {
                left: Box::new(first),
                right: Box::new(last),
                dfs_ordering: DfsOrdering::LeftRight,
            }
        } else {
            BranchNode {
                left: Box::new(last),
                right: Box::new(first),
                dfs_ordering: DfsOrdering::RightLeft,
            }
        }
    }

    /// Splits the structure into the left and right nodes, ordered according
    /// to bitcoin consensus rules (by the lexicographic order of the node
    /// hash values).
    #[inline]
    pub fn split(self) -> (TreeNode, TreeNode) { (*self.left, *self.right) }

    /// Splits the structure into the left and right nodes, ordered according
    /// to the original DFS order.
    #[inline]
    pub fn split_dfs(self) -> (TreeNode, TreeNode) {
        match self.dfs_ordering {
            DfsOrdering::LeftRight => (*self.left, *self.right),
            DfsOrdering::RightLeft => (*self.right, *self.left),
        }
    }

    /// Returns reference for to left (in bitcoin consensus lexicographic
    /// ordering) child node.
    #[inline]
    pub fn as_left_node(&self) -> &TreeNode { &self.left }

    /// Returns reference for to right (in bitcoin consensus lexicographic
    /// ordering) child node.
    #[inline]
    pub fn as_right_node(&self) -> &TreeNode { &self.right }

    /// Returns mutable reference to the left (in bitcoin consensus
    /// lexicographic ordering) child node.
    #[inline]
    pub(self) fn as_left_node_mut(&mut self) -> &mut TreeNode { &mut self.left }

    /// Returns reference to the right (in bitcoin consensus lexicographic
    /// ordering) child node.
    #[inline]
    pub(self) fn as_right_node_mut(&mut self) -> &mut TreeNode { &mut self.right }

    /// Returns reference to the child node at specific DFS `direction`.
    #[inline]
    pub fn as_dfs_child_node(&self, direction: DfsOrder) -> &TreeNode {
        match direction {
            DfsOrder::First => self.as_dfs_first_node(),
            DfsOrder::Last => self.as_dfs_last_node(),
        }
    }

    /// Returns reference to the first (in DFS ordering) child node.
    #[inline]
    pub fn as_dfs_first_node(&self) -> &TreeNode {
        match self.dfs_ordering() {
            DfsOrdering::LeftRight => self.as_left_node(),
            DfsOrdering::RightLeft => self.as_right_node(),
        }
    }

    /// Returns reference to the last (in DFS ordering) child node.
    #[inline]
    pub fn as_dfs_last_node(&self) -> &TreeNode {
        match self.dfs_ordering() {
            DfsOrdering::LeftRight => self.as_right_node(),
            DfsOrdering::RightLeft => self.as_left_node(),
        }
    }

    /// Returns mutable reference for the first (in DFS ordering) child node.
    #[inline]
    pub(self) fn as_dfs_first_node_mut(&mut self) -> &mut TreeNode {
        match self.dfs_ordering() {
            DfsOrdering::LeftRight => self.as_left_node_mut(),
            DfsOrdering::RightLeft => self.as_right_node_mut(),
        }
    }

    /// Returns mutable reference for the last (in DFS ordering) child node.
    #[inline]
    pub(self) fn as_dfs_last_node_mut(&mut self) -> &mut TreeNode {
        match self.dfs_ordering() {
            DfsOrdering::LeftRight => self.as_right_node_mut(),
            DfsOrdering::RightLeft => self.as_left_node_mut(),
        }
    }
}

/// Structure representing any complete node inside taproot script tree.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum TreeNode {
    /// Leaf script node. Keeps depth in the second tuple item.
    Leaf(LeafScript, u8),
    /// Hidden node, which may be a branch or a leaf node. Keeps depth in the
    /// second tuple item.
    Hidden(TapNodeHash, u8),
    /// Branch node. Keeps depth in the second tuple item.
    Branch(BranchNode, u8),
}

impl TreeNode {
    /// Constructs leaf tree node.
    pub fn with_tap_script(script: Script, depth: u8) -> TreeNode {
        TreeNode::Leaf(
            LeafScript {
                version: LeafVersion::TapScript,
                script: script.into(),
            },
            depth,
        )
    }

    /// Constructs branch node without child information. To provide information
    /// about child nodes use [`PartialBranchNode::push_child`] method.
    pub fn with_branch(a: TreeNode, b: TreeNode, depth: u8) -> TreeNode {
        TreeNode::Branch(BranchNode::with(a, b), depth)
    }

    /// Returns reference to the inner branch node, or `None` for a leaf and
    /// hidden nodes.
    pub fn as_branch(&self) -> Option<&BranchNode> {
        match self {
            TreeNode::Branch(branch, _) => Some(branch),
            _ => None,
        }
    }

    /// Returns mutable reference to the inner branch node, or `None` for leaf
    /// and hidden nodes.
    pub(self) fn as_branch_mut(&mut self) -> Option<&mut BranchNode> {
        match self {
            TreeNode::Branch(branch, _) => Some(branch),
            _ => None,
        }
    }

    /// Returns reference to the inner leaf script, or `None` for a branch and
    /// hidden nodes.
    pub fn as_leaf_script(&self) -> Option<&LeafScript> {
        match self {
            TreeNode::Leaf(leaf_script, _) => Some(leaf_script),
            _ => None,
        }
    }

    /// Traverses tree using the given `path` argument and returns the node
    /// reference at the tip of the path.
    ///
    /// # Errors
    ///
    /// Returns [`DfsTraversalError`] if the path can't be traversed.
    #[inline]
    pub fn node_at(&self, path: impl AsRef<[DfsOrder]>) -> Result<&TreeNode, DfsTraversalError> {
        let mut curr = self;
        let mut past_steps = vec![];
        let path = path.as_ref();
        let mut iter = path.into_iter();
        for step in iter.by_ref() {
            past_steps.push(step);
            let branch = match curr {
                TreeNode::Branch(branch, _) => branch,
                TreeNode::Leaf(leaf_script, _) => {
                    return Err(DfsTraversalError::LeafNode {
                        leaf_script: leaf_script.clone(),
                        failed_path: DfsPath::with(past_steps),
                        path_leftover: iter.collect(),
                    })
                }
                TreeNode::Hidden(hash, _) => {
                    return Err(DfsTraversalError::HiddenNode {
                        node_hash: *hash,
                        failed_path: DfsPath::with(past_steps),
                        path_leftover: iter.collect(),
                    })
                }
            };
            curr = match step {
                DfsOrder::First => branch.as_dfs_first_node(),
                DfsOrder::Last => branch.as_dfs_last_node(),
            };
        }
        Ok(curr)
    }

    /// Traverses tree using the given `path` argument and returns the node
    /// mutable reference at the tip of the path.
    ///
    /// # Errors
    ///
    /// Returns [`DfsTraversalError`] if the path can't be traversed.
    #[inline]
    pub(self) fn node_mut_at<'path>(
        &mut self,
        path: impl IntoIterator<Item = &'path DfsOrder>,
    ) -> Result<&mut TreeNode, DfsTraversalError> {
        let mut curr = self;
        let mut past_steps = vec![];
        let mut iter = path.into_iter();
        for step in iter.by_ref() {
            past_steps.push(step);
            let branch = match curr {
                TreeNode::Branch(branch, _) => branch,
                TreeNode::Leaf(leaf_script, _) => {
                    return Err(DfsTraversalError::LeafNode {
                        leaf_script: leaf_script.clone(),
                        failed_path: DfsPath::with(past_steps),
                        path_leftover: iter.collect(),
                    })
                }
                TreeNode::Hidden(hash, _) => {
                    return Err(DfsTraversalError::HiddenNode {
                        node_hash: *hash,
                        failed_path: DfsPath::with(past_steps),
                        path_leftover: iter.collect(),
                    })
                }
            };
            curr = match step {
                DfsOrder::First => branch.as_dfs_first_node_mut(),
                DfsOrder::Last => branch.as_dfs_last_node_mut(),
            };
        }
        Ok(curr)
    }

    /// Returns iterator over all subnodes on a given path.
    pub(self) fn nodes_on_path<'node, 'path>(
        &'node self,
        path: &'path [DfsOrder],
    ) -> TreePathIter<'node, 'path> {
        let path = path.as_ref();
        TreePathIter {
            next_node: Some(self),
            full_path: path,
            remaining_path: path.iter(),
        }
    }

    /// Returns iterator over all subnodes for this node.
    pub(self) fn nodes(&self) -> TreeNodeIter { TreeNodeIter::from(self) }

    pub(self) fn nodes_mut(&mut self) -> TreeNodeIterMut { TreeNodeIterMut::from(self) }

    pub(self) fn lower(&mut self, inc: u8) -> Result<u8, MaxDepthExceeded> {
        let old_depth = self.node_depth();
        match self {
            TreeNode::Leaf(_, depth) | TreeNode::Hidden(_, depth) | TreeNode::Branch(_, depth) => {
                *depth = depth.checked_add(inc).ok_or(MaxDepthExceeded)?;
            }
        }
        Ok(old_depth)
    }

    pub(self) fn raise(&mut self, dec: u8) -> Result<u8, RaiseAboveRoot> {
        let old_depth = self.node_depth();
        match self {
            TreeNode::Leaf(_, depth) | TreeNode::Hidden(_, depth) | TreeNode::Branch(_, depth) => {
                *depth = depth.checked_sub(dec).ok_or(RaiseAboveRoot)?;
            }
        }
        Ok(old_depth)
    }

    /// Checks that the node and all subnodes has correct consensus ordering:
    /// left-side branch hash is less or equal than right-side branch hash.
    #[cfg(test)]
    pub(self) fn check(&self) -> bool {
        if let Some(branch) = self.as_branch() {
            if branch.left.node_hash() > branch.right.node_hash() {
                return false;
            }
            if !branch.left.check() || !branch.right.check() {
                return false;
            }
        }
        return true;
    }
}

impl Node for TreeNode {
    fn is_hidden(&self) -> bool { matches!(self, TreeNode::Hidden(..)) }

    fn is_branch(&self) -> bool { matches!(self, TreeNode::Branch(..)) }

    fn is_leaf(&self) -> bool { matches!(self, TreeNode::Leaf(..)) }

    fn node_hash(&self) -> TapNodeHash {
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
            ref node @ PartialTreeNode::Branch(ref branch, depth) => TreeNode::with_branch(
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
                depth,
            ),
        })
    }
}

impl Display for TreeNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for (node, path) in self.nodes() {
            match node {
                TreeNode::Leaf(leaf_script, depth) => {
                    writeln!(f, "{} ({}): {}", path, depth, leaf_script)?;
                }
                TreeNode::Hidden(hash, depth) => writeln!(f, "{} ({}): {}", path, depth, hash)?,
                TreeNode::Branch(_, _) => {}
            }
        }
        Ok(())
    }
}

/// Structure representing taproot branch node which does not have a complete
/// information about its childen.
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

    fn branch_hash(&self) -> TapBranchHash { self.hash }
}

impl PartialBranchNode {
    /// Constructs partial branch node without child node information using the
    /// provided node hash data. If the child nodes are not pushed later, this
    /// will correspond to a hidden tree node.
    pub fn with(hash: TapBranchHash) -> Self {
        PartialBranchNode {
            hash,
            first: None,
            second: None,
        }
    }

    /// Adds information about next child node into this branch.
    ///
    /// # Returns
    ///
    /// Mutable reference to the newly added child node, or `None` if the branch
    /// was already full (i.e. contained both child nodes).
    pub fn push_child(&mut self, child: PartialTreeNode) -> Option<&mut PartialTreeNode> {
        let child = Box::new(child);
        if let Some(first) = &self.first {
            if first.node_hash() == child.node_hash() {
                return self.first.as_deref_mut();
            }
        } else {
            self.first = Some(child);
            return self.first.as_deref_mut();
        }
        if let Some(second) = &self.second {
            if second.node_hash() == child.node_hash() {
                return self.second.as_deref_mut();
            } else {
                return None;
            }
        } else {
            self.second = Some(child);
            return self.second.as_deref_mut();
        }
    }

    /// Returns node hash.
    #[inline]
    pub fn node_hash(&self) -> TapNodeHash { TapNodeHash::from_inner(self.hash.into_inner()) }
}

/// Represents information about taproot script tree when some of the branches
/// are not complete.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum PartialTreeNode {
    /// Leaf script node. Keeps depth in the second tuple item.
    Leaf(LeafScript, u8),
    /// Partial branch node (see [`PartialBranchNode`]). Keeps depth in the
    /// second tuple item.
    Branch(PartialBranchNode, u8),
}

impl PartialTreeNode {
    /// Constructs leaf node.
    pub fn with_leaf(leaf_version: LeafVersion, script: Script, depth: u8) -> PartialTreeNode {
        PartialTreeNode::Leaf(LeafScript::with(leaf_version, script.into()), depth)
    }

    /// Constructs branch node without child information. To provide information
    /// about child nodes use [`PartialBranchNode::push_child`] method.
    pub fn with_branch(hash: TapBranchHash, depth: u8) -> PartialTreeNode {
        PartialTreeNode::Branch(PartialBranchNode::with(hash), depth)
    }

    /// Returns reference to the inner branch node, or `None` for the leaf
    /// nodes.
    pub fn as_branch(&self) -> Option<&PartialBranchNode> {
        match self {
            PartialTreeNode::Leaf(_, _) => None,
            PartialTreeNode::Branch(branch, _) => Some(branch),
        }
    }

    /// Returns mutable reference to the inner branch node, or `None` for the
    /// leaf nodes.
    pub fn as_branch_mut(&mut self) -> Option<&mut PartialBranchNode> {
        match self {
            PartialTreeNode::Leaf(_, _) => None,
            PartialTreeNode::Branch(branch, _) => Some(branch),
        }
    }
}

impl Node for PartialTreeNode {
    #[inline]
    fn is_hidden(&self) -> bool { false }

    fn is_branch(&self) -> bool { matches!(self, PartialTreeNode::Branch(..)) }

    fn is_leaf(&self) -> bool { matches!(self, PartialTreeNode::Leaf(..)) }

    fn node_hash(&self) -> TapNodeHash {
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

/// Taproot script tree which keeps internal information in a tree data
/// structure, which can be modified by adding or removing parts of the tree
/// (subtrees). See [`Self::join`], [`Self::split`], [`Self::instill`],
/// [`Self::cut`] operations.
///
/// The structure can be build out of (or converted into) [`TapTree`] taproot
/// tree representation, which doesn't have a modifiable tree structure.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display("{root}")]
pub struct TaprootScriptTree {
    root: TreeNode,
}

impl AsRef<TreeNode> for TaprootScriptTree {
    #[inline]
    fn as_ref(&self) -> &TreeNode { &self.root }
}

impl Borrow<TreeNode> for TaprootScriptTree {
    #[inline]
    fn borrow(&self) -> &TreeNode { &self.root }
}

impl BorrowMut<TreeNode> for TaprootScriptTree {
    #[inline]
    fn borrow_mut(&mut self) -> &mut TreeNode { &mut self.root }
}

impl TaprootScriptTree {
    /// Returns iterator over known scripts stored in the tree.
    ///
    /// NB: the iterator ignores scripts behind hidden nodes.
    #[inline]
    pub fn scripts(&self) -> TreeScriptIter { TreeScriptIter::from(self) }

    /// Returns iterator over all known nodes of the tree.
    #[inline]
    pub fn nodes(&self) -> TreeNodeIter { TreeNodeIter::from(self) }

    /// Returns mutable iterator over all known nodes of the tree.
    #[inline]
    pub(self) fn nodes_mut(&mut self) -> TreeNodeIterMut { TreeNodeIterMut::from(self) }

    /// Returns iterator over all subnodes on a given path.
    pub fn nodes_on_path<'node, 'path>(
        &'node self,
        path: &'path [DfsOrder],
    ) -> TreePathIter<'node, 'path> {
        self.root.nodes_on_path(path)
    }

    /// Traverses tree using the provided path in DFS order and returns the
    /// node reference at the tip of the path.
    ///
    /// # Errors
    ///
    /// Returns [`DfsTraversalError`] if the path can't be traversed.
    #[inline]
    pub fn node_at(&self, path: impl AsRef<[DfsOrder]>) -> Result<&TreeNode, DfsTraversalError> {
        self.root.node_at(path)
    }

    /// Traverses tree using the provided path in DFS order and returns the
    /// mutable node reference at the tip of the path.
    ///
    /// # Errors
    ///
    /// Returns [`DfsTraversalError`] if the path can't be traversed.
    #[inline]
    pub(self) fn node_mut_at<'path>(
        &mut self,
        path: impl IntoIterator<Item = &'path DfsOrder>,
    ) -> Result<&mut TreeNode, DfsTraversalError> {
        self.root.node_mut_at(path)
    }

    fn update_ancestors_ordering(&mut self, path: &[DfsOrder]) {
        // Update DFS ordering of the nodes above
        for step in (0..path.len()).rev() {
            let ancestor = self
                .node_mut_at(&path[..step])
                .expect("the path must be checked to be valid");
            let branch = if let Some(branch) = ancestor.as_branch_mut() {
                branch
            } else {
                return;
            };
            if branch.left.node_hash() > branch.right.node_hash() {
                branch.dfs_ordering = !branch.dfs_ordering;
                let old_left = branch.as_left_node().clone();
                let old_right = branch.as_right_node().clone();
                let left = branch.as_left_node_mut();
                *left = old_right;
                let right = branch.as_right_node_mut();
                *right = old_left;
            }
        }
    }

    /// Joins two trees together under a new root.
    ///
    /// Creates a new tree with the root node containing `self` and `other_tree`
    /// as its direct children. The `other_tree` is put into `other_dfs_order`
    /// side.
    #[inline]
    pub fn join(
        mut self,
        other_tree: TaprootScriptTree,
        other_dfs_order: DfsOrder,
    ) -> Result<TaprootScriptTree, MaxDepthExceeded> {
        self.instill(other_tree, &[], other_dfs_order)
            .map_err(|_| MaxDepthExceeded)?;
        Ok(self)
    }

    /// Splits the tree into two subtrees. Errors if the tree root is hidden or
    /// a script leaf.
    ///
    /// # Returns
    ///
    /// Two child nodes under the root of the original tree as a new taproot
    /// script trees in the original DFS ordering.
    pub fn split(self) -> Result<(TaprootScriptTree, TaprootScriptTree), UnsplittableTree> {
        self.cut([], DfsOrder::First).map_err(|_| UnsplittableTree)
    }

    /// Instills `other_tree` as a subtree under provided `path` by creating a
    /// new branch node at the `path` and putting `other_tree` on the `dfs_side`
    /// of it.
    ///
    /// # Error
    ///
    /// Returns [`InstillError`] when the given path can't be traversed or
    /// the resulting tree depth exceeds taproot tree depth limit.
    pub fn instill<'path>(
        &mut self,
        mut other_tree: TaprootScriptTree,
        path: impl AsRef<[DfsOrder]>,
        dfs_order: DfsOrder,
    ) -> Result<(), InstillError> {
        let path = path.as_ref();
        let depth: u8 = path.len().try_into().map_err(|_| MaxDepthExceeded)?;

        let instill_point = self.node_mut_at(path)?;
        for n in instill_point.nodes_mut() {
            n.lower(1)?;
        }
        for n in other_tree.nodes_mut() {
            n.lower(depth.checked_add(1).ok_or(MaxDepthExceeded)?)?;
        }
        let instill_root = other_tree.into_root_node();
        let branch = if dfs_order == DfsOrder::First {
            BranchNode::with(instill_root, instill_point.clone())
        } else {
            BranchNode::with(instill_point.clone(), instill_root)
        };
        *instill_point = TreeNode::Branch(branch, depth);

        // Update DFS ordering of the nodes above
        self.update_ancestors_ordering(path);

        Ok(())
    }

    /// Cuts subtree out of this tree at the `path`, returning this tree without
    /// the cut branch and the cut subtree as a new tree.
    ///
    /// # Returns
    ///
    /// Modified original tree without the cut node and a new tree constructed
    /// out of the cut node.
    ///
    /// # Error
    ///
    /// Returns [`DfsTraversalError`] when the given path can't be traversed or
    /// points at an unsplittable node (leaf node or a hidden node).
    pub fn cut(
        mut self,
        path: impl AsRef<[DfsOrder]>,
        dfs_side: DfsOrder,
    ) -> Result<(TaprootScriptTree, TaprootScriptTree), CutError> {
        let path = path.as_ref();
        let depth: u8 = path
            .len()
            .try_into()
            .map_err(|_| DfsTraversalError::PathNotExists(path.to_vec().into()))?;

        let (mut cut, mut remnant) = match self.node_at(path)? {
            TreeNode::Leaf(_, _) | TreeNode::Hidden(_, _) => {
                return Err(CutError::UnsplittableTree)
            }
            TreeNode::Branch(branch, _) if dfs_side == DfsOrder::First => {
                branch.clone().split_dfs()
            }
            TreeNode::Branch(branch, _) => {
                let (remnant, cut) = branch.clone().split_dfs();
                (cut, remnant)
            }
        };

        for n in cut.nodes_mut() {
            n.raise(depth + 1)
                .expect("broken taproot tree cut algorithm");
        }
        for n in remnant.nodes_mut() {
            n.raise(1).expect("broken taproot tree cut algorithm");
        }

        let mut path_iter = path.iter();
        if let Some(last_step) = path_iter.next_back() {
            let cut_parent = self.node_mut_at(path_iter)?;
            let parent_branch_node = cut_parent
                .as_branch_mut()
                .expect("parent node always a branch node at this point");
            let replaced_child = match last_step {
                DfsOrder::First => parent_branch_node.as_dfs_first_node_mut(),
                DfsOrder::Last => parent_branch_node.as_dfs_last_node_mut(),
            };
            *replaced_child = remnant;
        } else {
            self = TaprootScriptTree { root: remnant };
        }

        let subtree = TaprootScriptTree { root: cut };

        // Update DFS ordering of the nodes above
        self.update_ancestors_ordering(path);

        Ok((self, subtree))
    }

    /// Returns reference to the root node of the tree.
    #[inline]
    pub fn as_root_node(&self) -> &TreeNode { &self.root }

    /// Consumes the tree and returns instance of the root node of the tree.
    #[inline]
    pub fn into_root_node(self) -> TreeNode { self.root }

    /// Returns a cloned root node.
    #[inline]
    pub fn to_root_node(&self) -> TreeNode { self.root.clone() }

    /// Checks that all nodes in the tree have correct consensus ordering:
    /// left-side branch hash is less or equal than right-side branch hash.
    #[cfg(test)]
    pub(crate) fn check(&self) -> bool { self.root.check() }
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
                            node = branch.push_child(child).expect("broken TapTree structure");
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

/// Iterator over tree nodes on a path.
pub struct TreePathIter<'tree, 'path> {
    next_node: Option<&'tree TreeNode>,
    full_path: &'path [DfsOrder],
    remaining_path: core::slice::Iter<'path, DfsOrder>,
}

impl<'tree, 'path> Iterator for TreePathIter<'tree, 'path> {
    type Item = Result<&'tree TreeNode, DfsTraversalError>;

    fn next(&mut self) -> Option<Self::Item> {
        match (self.next_node, self.remaining_path.next()) {
            (Some(curr_node), Some(step)) => {
                match curr_node.node_at([*step]) {
                    Err(err) => return Some(Err(err)),
                    Ok(next_node) => self.next_node = Some(next_node),
                }
                Some(Ok(curr_node))
            }
            (Some(curr_node), None) => {
                self.next_node = None;
                Some(Ok(curr_node))
            }
            (None, None) => None,
            (None, Some(_)) => Some(Err(DfsTraversalError::PathNotExists(DfsPath::with(
                self.full_path,
            )))),
        }
    }
}

/// Iterator over tree nodes.
pub struct TreeNodeIter<'tree> {
    stack: Vec<(&'tree TreeNode, DfsPath)>,
}

impl<'tree, T> From<&'tree T> for TreeNodeIter<'tree>
where
    T: Borrow<TreeNode>,
{
    fn from(tree: &'tree T) -> Self {
        TreeNodeIter {
            stack: vec![(tree.borrow(), DfsPath::new())],
        }
    }
}

impl<'tree> Iterator for TreeNodeIter<'tree> {
    type Item = (&'tree TreeNode, DfsPath);

    fn next(&mut self) -> Option<Self::Item> {
        let (curr, path) = self.stack.pop()?;
        if let TreeNode::Branch(branch, _) = curr {
            let mut p = path.clone();
            p.push(DfsOrder::First);
            self.stack.push((branch.as_dfs_first_node(), p.clone()));
            p.pop();
            p.push(DfsOrder::Last);
            self.stack.push((branch.as_dfs_last_node(), p));
        }
        Some((curr, path))
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
        Some(curr)
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
enum BranchDirection {
    Shallow,
    Deep,
}

/// Iterator over leaf scripts stored in the leaf nodes of the taproot script
/// tree.
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
    fn into_iter(self) -> Self::IntoIter { self.scripts() }
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
    fn from(tree: TaprootScriptTree) -> Self { TapTree::from(&tree) }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeSet;

    use bitcoin::blockdata::opcodes::all;
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

        let scripts = taptree.iter().collect::<BTreeSet<_>>();
        let scripts_prime = script_tree
            .scripts()
            .map(|(depth, leaf_script)| (depth, leaf_script.script.as_inner()))
            .collect::<BTreeSet<_>>();
        assert_eq!(scripts, scripts_prime);

        let taptree_prime = TapTree::from(&script_tree);
        assert_eq!(taptree, taptree_prime);
    }

    fn test_join_split(depth_map: impl IntoIterator<Item = u8>) {
        let taptree = compose_tree(0x51, depth_map);
        let script_tree = TaprootScriptTree::from(taptree.clone());
        assert!(script_tree.check());

        let instill_tree: TaprootScriptTree = compose_tree(all::OP_RETURN.into_u8(), [0]).into();
        let merged_tree = script_tree
            .clone()
            .join(instill_tree.clone(), DfsOrder::First)
            .unwrap();
        assert!(merged_tree.check());

        let _ = TapTree::from(&merged_tree);
        assert_ne!(merged_tree, script_tree);

        let order = merged_tree.root.as_branch().unwrap().dfs_ordering;

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

        let (script_tree_prime, instill_tree_prime) = merged_tree.split().unwrap();
        assert!(script_tree_prime.check());
        assert!(instill_tree_prime.check());

        assert_eq!(instill_tree, instill_tree_prime);
        assert_eq!(script_tree, script_tree_prime);
    }

    fn test_instill_cut(
        depth_map1: impl IntoIterator<Item = u8>,
        depth_map2: impl IntoIterator<Item = u8>,
        path: &str,
    ) {
        let path = DfsPath::from_str(path).unwrap();

        let taptree = compose_tree(0x51, depth_map1);
        let script_tree = TaprootScriptTree::from(taptree.clone());
        assert!(script_tree.check());

        let instill_tree: TaprootScriptTree = compose_tree(50, depth_map2).into();
        assert!(instill_tree.check());

        let mut merged_tree = script_tree.clone();
        merged_tree
            .instill(instill_tree.clone(), &path, DfsOrder::First)
            .unwrap();
        assert!(merged_tree.check());

        let _ = TapTree::from(&merged_tree);
        assert_ne!(merged_tree, script_tree);

        let (script_tree_prime, instill_tree_prime) =
            merged_tree.cut(path, DfsOrder::First).unwrap();

        assert!(script_tree_prime.check());
        assert!(instill_tree_prime.check());

        assert_eq!(instill_tree, instill_tree_prime);
        assert_eq!(script_tree, script_tree_prime);
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
    fn taptree_join_split() {
        test_join_split([0]);
        test_join_split([1, 1]);
        test_join_split([1, 2, 2]);
        test_join_split([2, 2, 2, 2]);
        test_join_split([1, 2, 3, 3]);
        test_join_split([1, 3, 3, 3, 3]);
        test_join_split([2, 2, 2, 3, 3]);
        test_join_split([2, 2, 3, 3, 3, 3]);
        test_join_split([2, 3, 3, 3, 3, 3, 3]);
        test_join_split([3, 3, 3, 3, 3, 3, 3, 3]);
    }

    #[test]
    fn taptree_instill_cut() {
        // Use a tree as shown below for a main tree
        // A, B , C are at depth 2 and D, E are at 3
        //                                       ....
        //                                     /      \
        //                                    /\      /\
        //                                   /  \    /  \
        //                                  A    B  C  / \
        //                                            D   E
        // Paths to nodes:
        // A: 00
        // B: 01
        // C: 10
        // D: 110
        // C: 111

        // Try instilling a single leaf
        test_instill_cut([2, 2, 2, 3, 3], [0], "");
        test_instill_cut([2, 2, 2, 3, 3], [0], "0");
        test_instill_cut([2, 2, 2, 3, 3], [0], "1");
        test_instill_cut([2, 2, 2, 3, 3], [0], "00");
        test_instill_cut([2, 2, 2, 3, 3], [0], "01");
        test_instill_cut([2, 2, 2, 3, 3], [0], "10");
        test_instill_cut([2, 2, 2, 3, 3], [0], "11");
        test_instill_cut([2, 2, 2, 3, 3], [0], "110");
        test_instill_cut([2, 2, 2, 3, 3], [0], "111");

        // Try instilling a subtree
        test_instill_cut([2, 2, 2, 3, 3], [1, 2, 3, 3], "");
        test_instill_cut([2, 2, 2, 3, 3], [1, 2, 3, 3], "0");
        test_instill_cut([2, 2, 2, 3, 3], [1, 2, 3, 3], "1");
        test_instill_cut([2, 2, 2, 3, 3], [1, 2, 3, 3], "00");
        test_instill_cut([2, 2, 2, 3, 3], [1, 2, 3, 3], "01");
        test_instill_cut([2, 2, 2, 3, 3], [1, 2, 3, 3], "10");
        test_instill_cut([2, 2, 2, 3, 3], [1, 2, 3, 3], "11");
        test_instill_cut([2, 2, 2, 3, 3], [1, 2, 3, 3], "110");
        test_instill_cut([2, 2, 2, 3, 3], [1, 2, 3, 3], "111");
    }

    #[test]
    fn instll_path_proof() {
        let path = DfsPath::from_str("00101").unwrap();

        let taptree = compose_tree(0x51, [3, 5, 5, 4, 3, 3, 2, 3, 4, 5, 6, 8, 8, 7]);
        let script_tree = TaprootScriptTree::from(taptree.clone());
        assert!(script_tree.check());
        println!("{}", script_tree);

        let instill_tree: TaprootScriptTree = compose_tree(50, [2, 2, 2, 3, 3]).into();
        assert!(instill_tree.check());

        let mut merged_tree = script_tree.clone();
        merged_tree
            .instill(instill_tree.clone(), &path, DfsOrder::First)
            .unwrap();
        assert!(merged_tree.check());

        #[derive(PartialEq, Eq, Debug)]
        enum PartnerNode {
            Script(String),
            Hash(TapNodeHash),
        }

        let path_partners = merged_tree
            .nodes_on_path(&path)
            .zip(&path)
            .map(|(node, step)| {
                let branch = node.unwrap().as_branch().unwrap();
                match branch.as_dfs_child_node(!step) {
                    TreeNode::Leaf(script, _) => {
                        PartnerNode::Script(script.script.as_inner().to_string())
                    }
                    TreeNode::Hidden(node, _) => PartnerNode::Hash(*node),
                    TreeNode::Branch(node, _) => {
                        PartnerNode::Hash(node.branch_hash().into_node_hash())
                    }
                }
            })
            .collect::<Vec<_>>();

        println!("{:#?}", path_partners);

        assert_eq!(path_partners, vec![
            PartnerNode::Hash(
                "e1cc80c5229fa380040f65495b5a7adf102ec6b1bfe51b5c3dbda04ee258529f"
                    .parse()
                    .unwrap()
            ),
            PartnerNode::Hash(
                "ddad73a07b9a7725185f19d6772b02bd4b3a5525d05afde705c186cdcf588c37"
                    .parse()
                    .unwrap()
            ),
            PartnerNode::Script(s!("Script(OP_PUSHNUM_1)")),
            PartnerNode::Script(s!("Script(OP_PUSHNUM_4)")),
            PartnerNode::Script(s!("Script(OP_PUSHNUM_2)")),
        ]);
    }
}
