// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0


mod definition;

use crate::account::AccountStateBlob;
use crate::Result;

use crate::hasher::{
        CryptoHash, CryptoHasher, SparseMerkleInternalHasher,
        SparseMerkleLeafHasher, SPARSE_MERKLE_PLACEHOLDER_HASH,
    HashValue,
};
use crate::failure::prelude::*;
use std::{collections::VecDeque, marker::PhantomData};

pub use crate::proof::definition::{
   SparseMerkleProof,
};



/// If `element_blob` is present, verifies an element whose key is `element_key` and value
/// is `element_blob` exists in the Sparse Merkle Tree using the provided proof.
/// Otherwise verifies the proof is a valid non-inclusion proof that shows this key doesn't exist
/// in the tree.
pub fn verify_sparse_merkle_element(
    expected_root_hash: HashValue,
    element_key: HashValue,
    element_blob: &Option<AccountStateBlob>,
    sparse_merkle_proof: &SparseMerkleProof,
) -> Result<()> {
    let siblings = sparse_merkle_proof.siblings();
    ensure!(
        siblings.len() <= HashValue::LENGTH_IN_BITS,
        "Sparse Merkle Tree proof has more than {} ({}) siblings.",
        HashValue::LENGTH_IN_BITS,
        siblings.len()
    );

    match (element_blob, sparse_merkle_proof.leaf()) {
        (Some(blob), Some((proof_key, proof_value_hash))) => {
            // This is an inclusion proof, so the key and value hash provided in the proof should
            // match element_key and element_value_hash.
            // `siblings` should prove the route from the leaf node to the root.
            ensure!(
                element_key == proof_key,
                "Keys do not match. Key in proof: {:x}. Expected key: {:x}.",
                proof_key,
                element_key
            );
            let hash = blob.hash();
            ensure!(
                hash == proof_value_hash,
                "Value hashes do not match. Value hash in proof: {:x}. Expected value hash: {:x}",
                proof_value_hash,
                hash,
            );
        }
        (Some(_blob), None) => bail!("Expected inclusion proof. Found non-inclusion proof."),
        (None, Some((proof_key, _))) => {
            // This is a non-inclusion proof.
            // The proof intends to show that if a leaf node representing `element_key` is inserted,
            // it will break a currently existing leaf node represented by `proof_key` into a
            // branch.
            // `siblings` should prove the route from that leaf node to the root.
            ensure!(
                element_key != proof_key,
                "Expected non-inclusion proof, but key exists in proof."
            );
            ensure!(
                element_key.common_prefix_bits_len(proof_key) >= siblings.len(),
                "Key would not have ended up in the subtree where the provided key in proof is \
                 the only existing key, if it existed. So this is not a valid non-inclusion proof."
            );
        }
        (None, None) => {
            // This is a non-inclusion proof.
            // The proof intends to show that if a leaf node representing `element_key` is inserted,
            // it will show up at a currently empty position.
            // `sibling` should prove the route from this empty position to the root.
        }
    }

    let current_hash = match sparse_merkle_proof.leaf() {
        Some((key, value_hash)) => SparseMerkleLeafNode::new(key, value_hash).hash(),
        None => *SPARSE_MERKLE_PLACEHOLDER_HASH,
    };
    let actual_root_hash = siblings
        .iter()
        .rev()
        .zip(
            element_key
                .iter_bits()
                .rev()
                .skip(HashValue::LENGTH_IN_BITS - siblings.len()),
        )
        .fold(current_hash, |hash, (sibling_hash, bit)| {
            if bit {
                SparseMerkleInternalNode::new(*sibling_hash, hash).hash()
            } else {
                SparseMerkleInternalNode::new(hash, *sibling_hash).hash()
            }
        });
    ensure!(
        actual_root_hash == expected_root_hash,
        "Root hashes do not match. Actual root hash: {:x}. Expected root hash: {:x}.",
        actual_root_hash,
        expected_root_hash
    );

    Ok(())
}

pub struct MerkleTreeInternalNode<H> {
    left_child: HashValue,
    right_child: HashValue,
    hasher: PhantomData<H>,
}

impl<H: CryptoHasher> MerkleTreeInternalNode<H> {
    pub fn new(left_child: HashValue, right_child: HashValue) -> Self {
        Self {
            left_child,
            right_child,
            hasher: PhantomData,
        }
    }
}

impl<H: CryptoHasher> CryptoHash for MerkleTreeInternalNode<H> {
    type Hasher = H;

    fn hash(&self) -> HashValue {
        let mut state = Self::Hasher::default();
        state.write(self.left_child.as_ref());
        state.write(self.right_child.as_ref());
        state.finish()
    }
}

pub type SparseMerkleInternalNode = MerkleTreeInternalNode<SparseMerkleInternalHasher>;

pub struct SparseMerkleLeafNode {
    key: HashValue,
    value_hash: HashValue,
}

impl SparseMerkleLeafNode {
    pub fn new(key: HashValue, value_hash: HashValue) -> Self {
        SparseMerkleLeafNode { key, value_hash }
    }
}

impl CryptoHash for SparseMerkleLeafNode {
    type Hasher = SparseMerkleLeafHasher;

    fn hash(&self) -> HashValue {
        let mut state = Self::Hasher::default();
        state.write(self.key.as_ref());
        state.write(self.value_hash.as_ref());
        state.finish()
    }
}
