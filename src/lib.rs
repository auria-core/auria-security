// File: lib.rs - This file is part of AURIA
// Copyright (c) 2026 AURIA Developers and Contributors
// Description:
//     Cryptographic operations for AURIA Runtime Core.
//     Provides functions for shard integrity verification using BLAKE3,
//     hash computation, and signature verification.
//
pub mod crypto;

use auria_core::error::AuriaResult;
use auria_core::AuriaError;
use auria_core::shard::{Hash, PublicKey, Signature, Shard};
use crate::crypto::SecurityError;

pub fn verify_shard_integrity(shard: &Shard) -> AuriaResult<bool> {
    let data = &shard.tensor.data;
    let computed = blake3::hash(data);
    let hash = Hash(*computed.as_bytes());
    if let Some(license_hash) = &shard.metadata.license_hash {
        Ok(&hash == license_hash)
    } else {
        Ok(true)
    }
}

pub fn verify_signature(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> AuriaResult<bool> {
    crypto::verify_signature_core(public_key, message, signature)
        .map_err(|e| AuriaError::SecurityError(e.to_string()))
}

pub fn compute_hash(data: &[u8]) -> Hash {
    let h = blake3::hash(data);
    Hash(*h.as_bytes())
}
