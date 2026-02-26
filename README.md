# auria-security

Cryptographic operations for AURIA Runtime Core.

## Features

- Shard integrity verification using BLAKE3
- Signature verification using Ed25519
- Hash computation (BLAKE3, SHA3)

## Functions

- `verify_shard_integrity()` - Verify shard data integrity
- `verify_signature()` - Verify cryptographic signatures
- `compute_hash()` - Compute cryptographic hashes

## Usage

```rust
use auria_security::{verify_shard_integrity, compute_hash};

let is_valid = verify_shard_integrity(&shard)?;
let hash = compute_hash(&data);
```
