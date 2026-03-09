// File: crypto.rs - This file is part of AURIA
// Copyright (c) 2026 AURIA Developers and Contributors
// Description:
//     Cryptographic primitives for AURIA Runtime Core.
//     Provides secure hash functions, digital signatures, and key generation.

use rand::Rng;
use rand::rngs::OsRng;
use sha3::{Digest, Keccak256, Keccak512};
use blake3;
use ed25519_dalek::{Signer, Verifier, Keypair, PublicKey as EdPublicKey, Signature as EdSignature};
use std::convert::TryInto;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub fn new() -> Self {
        let mut rng = OsRng::default();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(hex: &str) -> SecurityResult<Self> {
        let bytes = hex::decode(hex)
            .map_err(|_| SecurityError::HashVerificationFailed)?;
        if bytes.len() != 32 {
            return Err(SecurityError::HashVerificationFailed);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Hash({})", self.to_hex())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl Signature {
    pub fn new() -> Self {
        let mut rng = OsRng::default();
        let mut bytes = [0u8; 64];
        rng.fill(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Signature({})", self.to_hex())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    pub fn new() -> Self {
        let mut rng = OsRng::default();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateKey(pub [u8; 32]);

impl PrivateKey {
    pub fn new() -> Self {
        let mut rng = OsRng::default();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "PrivateKey({})", self.to_hex())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub public: PublicKey,
    pub private: PrivateKey,
}

impl KeyPair {
    pub fn new() -> SecurityResult<Self> {
        let keypair = ed25519_dalek::Keypair::generate(&mut OsRng::default());
        let public = PublicKey(keypair.public.as_bytes().try_into().unwrap());
        let private = PrivateKey(keypair.secret.as_bytes().try_into().unwrap());
        Ok(Self { public, private })
    }

    pub fn from_keypair(keypair: ed25519_dalek::Keypair) -> Self {
        let public = PublicKey(keypair.public.as_bytes().try_into().unwrap());
        let private = PrivateKey(keypair.secret.as_bytes().try_into().unwrap());
        Self { public, private }
    }

    pub fn to_keypair(&self) -> ed25519_dalek::Keypair {
        let public = ed25519_dalek::PublicKey::from_bytes(&self.public.0).unwrap();
        let private = ed25519_dalek::SecretKey::from_bytes(&self.private.0).unwrap();
        ed25519_dalek::Keypair { public, secret: private }
    }

    pub fn sign(&self, message: &[u8]) -> SecurityResult<Signature> {
        let keypair = self.to_keypair();
        let signature = keypair.sign(message);
        Ok(Signature(signature.to_bytes()))
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> SecurityResult<bool> {
        let public = ed25519_dalek::PublicKey::from_bytes(&self.public.0)
            .map_err(|_| SecurityError::InvalidPublicKey)?;
        let ed_signature = ed25519_dalek::Signature::from_bytes(&signature.0)
            .map_err(|_| SecurityError::SignatureVerificationFailed)?;
        Ok(public.verify(message, &ed_signature).is_ok())
    }
}

pub fn blake3_hash(data: &[u8]) -> Hash {
    let h = blake3::hash(data);
    Hash(*h.as_bytes())
}

pub fn keccak256_hash(data: &[u8]) -> Hash {
    let h = Keccak256::digest(data);
    let mut result = [0u8; 32];
    result.copy_from_slice(&h);
    Hash(result)
}

pub fn keccak512_hash(data: &[u8]) -> [u8; 64] {
    let h = Keccak512::digest(data);
    let mut result = [0u8; 64];
    result.copy_from_slice(&h);
    result
}

pub fn verify_blake3_hash(data: &[u8], expected_hash: &Hash) -> SecurityResult<bool> {
    let computed = blake3_hash(data);
    Ok(computed == *expected_hash)
}

pub fn verify_keccak256_hash(data: &[u8], expected_hash: &Hash) -> SecurityResult<bool> {
    let computed = keccak256_hash(data);
    Ok(computed == *expected_hash)
}

pub fn generate_keypair() -> SecurityResult<KeyPair> {
    KeyPair::new()
}

pub fn sign_message(private_key: &PrivateKey, message: &[u8]) -> SecurityResult<Signature> {
    let keypair = ed25519_dalek::Keypair::from_secret(ed25519_dalek::SecretKey::from_bytes(&private_key.0)
        .map_err(|_| SecurityError::InvalidPrivateKey)?);
    let signature = keypair.sign(message);
    Ok(Signature(signature.to_bytes()))
}

pub fn verify_signature(public_key: &PublicKey, message: &[u8], signature: &Signature) -> SecurityResult<bool> {
    let public = ed25519_dalek::PublicKey::from_bytes(&public_key.0)
        .map_err(|_| SecurityError::InvalidPublicKey)?;
    let ed_signature = ed25519_dalek::Signature::from_bytes(&signature.0)
        .map_err(|_| SecurityError::SignatureVerificationFailed)?;
    Ok(public.verify(message, &ed_signature).is_ok())
}

pub fn derive_key_from_password(password: &str, salt: &[u8]) -> SecurityResult<PrivateKey> {
    use scrypt::Scrypt;
    let params = scrypt::ScryptParams::new(14, 8, 1);
    let mut key = [0u8; 32];
    Scrypt::default()
        .params(params)
        .salt(salt)
        .hash(password.as_bytes(), &mut key)
        .map_err(|_| SecurityError::KeyManagementError("SCrypt derivation failed".to_string()))?;
    Ok(PrivateKey(key))
}

pub fn generate_random_salt() -> [u8; 16] {
    let mut rng = OsRng::default();
    let mut salt = [0u8; 16];
    rng.fill(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_functions() {
        let data = b"test data";

        let blake3 = blake3_hash(data);
        let keccak = keccak256_hash(data);

        assert_ne!(blake3, keccak);
        assert_eq!(blake3.0.len(), 32);
        assert_eq!(keccak.0.len(), 32);
    }

    #[test]
    fn test_key_generation() {
        let keypair = generate_keypair().unwrap();

        assert_ne!(keypair.public, PublicKey([0u8; 32]));
        assert_ne!(keypair.private, PrivateKey([0u8; 32]));
        assert_eq!(keypair.public.0.len(), 32);
        assert_eq!(keypair.private.0.len(), 32);
    }

    #[test]
    fn test_sign_verify() {
        let keypair = generate_keypair().unwrap();
        let message = b"test message";

        let signature = sign_message(&keypair.private, message).unwrap();
        assert!(verify_signature(&keypair.public, message, &signature).unwrap());

        let invalid_message = b"wrong message";
        assert!(!verify_signature(&keypair.public, invalid_message, &signature).unwrap());
    }

    #[test]
    fn test_key_derivation() {
        let password = "secure password";
        let salt = generate_random_salt();

        let key1 = derive_key_from_password(password, &salt).unwrap();
        let key2 = derive_key_from_password(password, &salt).unwrap();

        assert_eq!(key1, key2);
        assert_ne!(key1, PrivateKey([0u8; 32]));
    }

    #[test]
    fn test_hash_hex_conversion() {
        let hash = blake3_hash(b"test");
        let hex = hash.to_hex();
        let decoded = Hash::from_hex(&hex).unwrap();

        assert_eq!(hash, decoded);
    }
}