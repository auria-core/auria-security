use auria_core::{AuriaResult, Hash, PublicKey, Shard, Signature};
use ed25519_dalek::Verifier;

pub fn verify_shard_integrity(shard: &Shard) -> AuriaResult<bool> {
    let data = &shard.tensor.data;
    let computed = blake3::hash(data);
    let hash = Hash(computed.as_bytes().clone());
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
    use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};
    let key = VerifyingKey::from_bytes(&public_key.0)
        .map_err(|_| auria_core::AuriaError::SecurityError("Invalid public key".to_string()))?;
    let sig = DalekSignature::from_bytes(&signature.0);
    Ok(key.verify(message, &sig).is_ok())
}

pub fn compute_hash(data: &[u8]) -> Hash {
    let h = blake3::hash(data);
    Hash(*h.as_bytes())
}
