// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unit_arg)]

//! This module has definition of various proofs.

use self::bitmap::{SparseMerkleBitmap};
use crate::hasher::{HashValue, SPARSE_MERKLE_PLACEHOLDER_HASH};

/// A proof that can be used to authenticate an element in a Sparse Merkle Tree given trusted root
/// hash. For example, `TransactionInfoToAccountProof` can be constructed on top of this structure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SparseMerkleProof {
    /// This proof can be used to authenticate whether a given leaf exists in the tree or not.
    ///     - If this is `Some(HashValue, HashValue)`
    ///         - If the first `HashValue` equals requested key, this is an inclusion proof and the
    ///           second `HashValue` equals the hash of the corresponding account blob.
    ///         - Otherwise this is a non-inclusion proof. The first `HashValue` is the only key
    ///           that exists in the subtree and the second `HashValue` equals the hash of the
    ///           corresponding account blob.
    ///     - If this is `None`, this is also a non-inclusion proof which indicates the subtree is
    ///       empty.
    leaf: Option<(HashValue, HashValue)>,

    /// All siblings in this proof, including the default ones. Siblings near the root are at the
    /// beginning of the vector.
    siblings: Vec<HashValue>,
}

impl SparseMerkleProof {
    /// Constructs a new `SparseMerkleProof` using leaf and a list of siblings.
    pub fn new(leaf: Option<(HashValue, HashValue)>, siblings: Vec<HashValue>) -> Self {
        // The sibling list could be empty in case the Sparse Merkle Tree is empty or has a single
        // element. When it's not empty, the bottom most sibling will never be default, otherwise a
        // leaf and a default sibling should have collapsed to a leaf.
        if let Some(last_sibling) = siblings.last() {
            assert_ne!(*last_sibling, *SPARSE_MERKLE_PLACEHOLDER_HASH);
        }

        SparseMerkleProof { leaf, siblings }
    }

    /// Returns the leaf node in this proof.
    pub fn leaf(&self) -> Option<(HashValue, HashValue)> {
        self.leaf
    }

    /// Returns the list of siblings in this proof.
    pub fn siblings(&self) -> &[HashValue] {
        &self.siblings
    }
}

mod bitmap {
    
    /// The bitmap indicating which siblings are default in a compressed sparse merkle proof. 1
    /// means non-default and 0 means default.  The MSB of the first byte corresponds to the
    /// sibling at the top of the Sparse Merkle Tree. The rightmost 1-bit of the last byte
    /// corresponds to the sibling at the bottom, since this one is always non-default.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct SparseMerkleBitmap(Vec<u8>);

    impl SparseMerkleBitmap {
        pub fn new(bitmap: Vec<u8>) -> Self {
            SparseMerkleBitmap(bitmap)
        }

        pub fn iter(&self) -> SparseMerkleBitmapIterator {
            SparseMerkleBitmapIterator::new(&self.0)
        }
    }

    impl std::convert::From<SparseMerkleBitmap> for Vec<u8> {
        fn from(bitmap: SparseMerkleBitmap) -> Vec<u8> {
            bitmap.0
        }
    }

    /// Given a `Vec<u8>` bitmap, this iterator generates one bit at a time starting from the MSB
    /// of the first byte. All trailing zeros of the last byte are discarded.
    pub struct SparseMerkleBitmapIterator<'a> {
        bitmap: &'a [u8],
        index: usize,
        len: usize,
    }

    impl<'a> SparseMerkleBitmapIterator<'a> {
        fn new(bitmap: &'a [u8]) -> Self {
            match bitmap.last() {
                Some(last_byte) => {
                    assert_ne!(
                        *last_byte, 0,
                        "The last byte of the bitmap should never be zero."
                    );
                    SparseMerkleBitmapIterator {
                        bitmap,
                        index: 0,
                        len: bitmap.len() * 8 - last_byte.trailing_zeros() as usize,
                    }
                }
                None => SparseMerkleBitmapIterator {
                    bitmap,
                    index: 0,
                    len: 0,
                },
            }
        }
    }

    impl<'a> std::iter::Iterator for SparseMerkleBitmapIterator<'a> {
        type Item = bool;

        fn next(&mut self) -> Option<bool> {
            // We are past the last useful bit.
            if self.index >= self.len {
                return None;
            }

            let pos = self.index / 8;
            let bit = self.index % 8;
            let ret = self.bitmap[pos] >> (7 - bit) & 1 != 0;
            self.index += 1;
            Some(ret)
        }
    }

    impl std::iter::FromIterator<bool> for SparseMerkleBitmap {
        fn from_iter<I>(iter: I) -> Self
        where
            I: std::iter::IntoIterator<Item = bool>,
        {
            let mut bitmap = vec![];
            for (i, bit) in iter.into_iter().enumerate() {
                let pos = i % 8;
                if pos == 0 {
                    bitmap.push(0);
                }
                let last_byte = bitmap
                    .last_mut()
                    .expect("The bitmap vector should not be empty");
                *last_byte |= (bit as u8) << (7 - pos);
            }
            SparseMerkleBitmap::new(bitmap)
        }
    }
}
