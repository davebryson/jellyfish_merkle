// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::hasher::{ HashValue,AccountStateBlobHasher, CryptoHash, CryptoHasher};
use hex;
use crate::failure::prelude::*;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, convert::TryFrom, fmt};

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccountStateBlob {
    blob: Vec<u8>,
}

impl fmt::Debug for AccountStateBlob {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "AccountStateBlob {{ \n \
             Raw: 0x{} \n \
             }}",
            hex::encode(&self.blob),
        )
    }
}

impl AsRef<[u8]> for AccountStateBlob {
    fn as_ref(&self) -> &[u8] {
        &self.blob
    }
}

impl From<AccountStateBlob> for Vec<u8> {
    fn from(account_state_blob: AccountStateBlob) -> Vec<u8> {
        account_state_blob.blob
    }
}

impl From<Vec<u8>> for AccountStateBlob {
    fn from(blob: Vec<u8>) -> AccountStateBlob {
        AccountStateBlob { blob }
    }
}

impl CryptoHash for AccountStateBlob {
    type Hasher = AccountStateBlobHasher;

    fn hash(&self) -> HashValue {
        let mut hasher = Self::Hasher::default();
        hasher.write(&self.blob);
        hasher.finish()
    }
}
