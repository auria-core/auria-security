// File: hardware_security.rs - This file is part of AURIA
// Copyright (c) 2026 AURIA Developers and Contributors
// Description:
//     Hardware security module for AURIA Runtime Core.
//     Provides secure hardware-backed cryptographic operations and key storage.
//     Interfaces with TPM, secure enclaves, and hardware security modules.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareSecurityModule {
    pub module_id: String,
    pub module_type: HardwareSecurityType,
    pub capabilities: Vec<String>,
    pub status: HardwareSecurityStatus,
    pub supported_algorithms: Vec<String>,
    pub max_key_size: usize,
    pub max_operations_per_second: u32,
    pub is_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[repr(u8)]
pub enum HardwareSecurityType {
    Tpm = 0,
    SecureEnclave = 1,
    TrustedExecutionEnvironment = 2,
    SmartCard = 3,
    HardwareSecurityModule = 4,
    Unknown = 255,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[repr(u8)]
pub enum HardwareSecurityStatus {
    Initializing = 0,
    Ready = 1,
    Busy = 2,
    Error = 3,
    Unavailable = 4,
    Unknown = 255,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareSecurityConfig {
    pub enabled: bool,
    pub module_type: HardwareSecurityType,
    pub timeout_ms: u64,
    pub retry_count: u32,
    pub retry_delay_ms: u64,
    pub cache_enabled: bool,
    pub cache_size: usize,
    pub audit_enabled: bool,
    pub audit_log_path: String,
}

impl Default for HardwareSecurityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            module_type: HardwareSecurityType::Tpm,
            timeout_ms: 30000,
            retry_count: 3,
            retry_delay_ms: 1000,
            cache_enabled: true,
            cache_size: 1024,
            audit_enabled: true,
            audit_log_path: "./logs/hsm_audit.log".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareSecurityError {
    pub error_code: u32,
    pub error_message: String,
    pub timestamp: u64,
    pub operation: String,
    pub module_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareSecurityOperation {
    pub operation_id: String,
    pub operation_type: String,
    pub input_data: Vec<u8>,
    pub output_data: Vec<u8>,
    pub status: HardwareSecurityOperationStatus,
    pub start_time: u64,
    pub end_time: u64,
    pub duration_ms: u64,
    pub error: Option<HardwareSecurityError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[repr(u8)]
pub enum HardwareSecurityOperationStatus {
    Pending = 0,
    InProgress = 1,
    Completed = 2,
    Failed = 3,
    Cancelled = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareSecurityKey {
    pub key_id: String,
    pub key_type: KeyType,
    pub algorithm: String,
    pub key_size_bits: u32,
    pub is_exportable: bool,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub permissions: Vec<String>,
    pub usage_count: u64,
    pub last_used: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareSecurityOperationResult {
    pub operation_id: String,
    pub success: bool,
    pub output: Vec<u8>,
    pub error: Option<HardwareSecurityError>,
    pub execution_time_ms: u64,
}

#[derive(Debug, Clone)]
pub struct HardwareSecurityManager {
    pub module: Arc<Mutex<HardwareSecurityModule>>,
    pub config: HardwareSecurityConfig,
    pub operation_cache: Arc<Mutex<HashMap<String, HardwareSecurityOperation>>>,
    pub audit_log: Arc<Mutex<Vec<HardwareSecurityOperation>>>,
}

impl HardwareSecurityManager {
    pub fn new(config: HardwareSecurityConfig) -> SecurityResult<Self> {
        let module = Self::initialize_module(&config)?;
        let operation_cache = Arc::new(Mutex::new(HashMap::new()));
        let audit_log = Arc::new(Mutex::new(Vec::new()));

        Ok(Self {
            module: Arc::new(Mutex::new(module)),
            config,
            operation_cache,
            audit_log,
        })
    }

    pub fn initialize_module(config: &HardwareSecurityConfig) -> SecurityResult<HardwareSecurityModule> {
        // Simulate hardware module initialization
        let module_id = format!("hsm_{}", Uuid::new_v4());
        let module_type = config.module_type;
        let capabilities = Self::detect_capabilities(module_type);
        let status = HardwareSecurityStatus::Ready;
        let supported_algorithms = Self::get_supported_algorithms(module_type);
        let max_key_size = Self::get_max_key_size(module_type);
        let max_operations_per_second = Self::get_max_operations_per_second(module_type);
        let is_available = true;

        Ok(HardwareSecurityModule {
            module_id,
            module_type,
            capabilities,
            status,
            supported_algorithms,
            max_key_size,
            max_operations_per_second,
            is_available,
        })
    }

    pub fn detect_capabilities(module_type: HardwareSecurityType) -> Vec<String> {
        match module_type {
            HardwareSecurityType::Tpm => vec![
                "tpm_2.0".to_string(),
                "key_generation".to_string(),
                "encryption".to_string(),
                "signing".to_string(),
                "attestation".to_string(),
            ],
            HardwareSecurityType::SecureEnclave => vec![
                "secure_enclave".to_string(),
                "key_storage".to_string(),
                "encryption".to_string(),
                "signing".to_string(),
                "isolation".to_string(),
            ],
            HardwareSecurityType::TrustedExecutionEnvironment => vec![
                "tee".to_string(),
                "confidential_computing".to_string(),
                "key_protection".to_string(),
                "secure_execution".to_string(),
            ],
            HardwareSecurityType::SmartCard => vec![
                "smart_card".to_string(),
                "pin_protection".to_string(),
                "key_storage".to_string(),
                "secure_execution".to_string(),
            ],
            HardwareSecurityType::HardwareSecurityModule => vec![
                "hsm".to_string(),
                "enterprise_security".to_string(),
                "high_performance".to_string(),
                "key_management".to_string(),
            ],
            _ => vec![],
        }
    }

    pub fn get_supported_algorithms(module_type: HardwareSecurityType) -> Vec<String> {
        match module_type {
            HardwareSecurityType::Tpm => vec![
                "rsa2048".to_string(),
                "rsa4096".to_string(),
                "ecdsa_p256".to_string(),
                "ecdsa_p384".to_string(),
                "sha256".to_string(),
                "sha384".to_string(),
                "sha512".to_string(),
            ],
            HardwareSecurityType::SecureEnclave => vec![
                "ecdsa_p256".to_string(),
                "ed25519".to_string(),
                "aes256".to_string(),
                "chacha20".to_string(),
                "sha256".to_string(),
            ],
            HardwareSecurityType::TrustedExecutionEnvironment => vec![
                "rsa3072".to_string(),
                "ecdsa_p384".to_string(),
                "aes256".to_string(),
                "sha512".to_string(),
                "hmac_sha256".to_string(),
            ],
            HardwareSecurityType::SmartCard => vec![
                "rsa2048".to_string(),
                "des3".to_string(),
                "aes128".to_string(),
                "sha1".to_string(),
                "md5".to_string(),
            ],
            HardwareSecurityType::HardwareSecurityModule => vec![
                "rsa4096".to_string(),
                "ecdsa_p521".to_string(),
                "ed448".to_string(),
                "aes256_gcm".to_string(),
                "sha3_512".to_string(),
                "argon2".to_string(),
            ],
            _ => vec![],
        }
    }

    pub fn get_max_key_size(module_type: HardwareSecurityType) -> usize {
        match module_type {
            HardwareSecurityType::Tpm => 4096,
            HardwareSecurityType::SecureEnclave => 256,
            HardwareSecurityType::TrustedExecutionEnvironment => 3072,
            HardwareSecurityType::SmartCard => 2048,
            HardwareSecurityType::HardwareSecurityModule => 8192,
            _ => 2048,
        }
    }

    pub fn get_max_operations_per_second(module_type: HardwareSecurityType) -> u32 {
        match module_type {
            HardwareSecurityType::Tpm => 100,
            HardwareSecurityType::SecureEnclave => 500,
            HardwareSecurityType::TrustedExecutionEnvironment => 1000,
            HardwareSecurityType::SmartCard => 50,
            HardwareSecurityType::HardwareSecurityModule => 10000,
            _ => 100,
        }
    }

    pub fn generate_key(&self, key_type: KeyType, algorithm: &str, key_size_bits: u32) -> SecurityResult<HardwareSecurityKey> {
        let module = self.module.lock().unwrap();

        // Validate algorithm
        if !module.supported_algorithms.contains(&algorithm.to_string()) {
            return Err(SecurityError::HardwareSecurityError(format!("Algorithm {} not supported", algorithm)));
        }

        // Validate key size
        if key_size_bits as usize > module.max_key_size {
            return Err(SecurityError::HardwareSecurityError(format!("Key size {} exceeds maximum {}", key_size_bits, module.max_key_size)));
        }

        // Simulate key generation
        let key_id = format!("hsm_key_{}", Uuid::new_v4());
        let created_at = Self::current_timestamp();
        let expires_at = Some(created_at + (365 * 24 * 60 * 60)); // 1 year
        let is_exportable = match key_type {
            KeyType::Asymmetric | KeyType::Symmetric => true,
            _ => false,
        };
        let permissions = match key_type {
            KeyType::Root => vec!["root_access".to_string(), "full_control".to_string()],
            KeyType::Node => vec!["node_authentication".to_string(), "node_communication".to_string()],
            KeyType::Shard => vec!["shard_encryption".to_string(), "shard_authentication".to_string()],
            _ => vec![],
        };

        let key = HardwareSecurityKey {
            key_id,
            key_type,
            algorithm: algorithm.to_string(),
            key_size_bits,
            is_exportable,
            created_at,
            expires_at,
            permissions,
            usage_count: 0,
            last_used: 0,
        };

        // Log operation
        self.log_operation("generate_key", key_id.clone(), Vec::new(), Vec::new())?;

        Ok(key)
    }

    pub fn import_key(&self, key_data: &[u8], key_type: KeyType, algorithm: &str) -> SecurityResult<HardwareSecurityKey> {
        let module = self.module.lock().unwrap();

        // Validate algorithm
        if !module.supported_algorithms.contains(&algorithm.to_string()) {
            return Err(SecurityError::HardwareSecurityError(format!("Algorithm {} not supported", algorithm)));
        }

        // Validate key data
        if key_data.is_empty() {
            return Err(SecurityError::HardwareSecurityError("Key data cannot be empty".to_string()));
        }

        // Simulate key import
        let key_id = format!("hsm_key_{}", Uuid::new_v4());
        let created_at = Self::current_timestamp();
        let expires_at = Some(created_at + (365 * 24 * 60 * 60)); // 1 year
        let is_exportable = match key_type {
            KeyType::Asymmetric | KeyType::Symmetric => true,
            _ => false,
        };
        let permissions = match key_type {
            KeyType::Root => vec!["root_access".to_string(), "full_control".to_string()],
            KeyType::Node => vec!["node_authentication".to_string(), "node_communication".to_string()],
            KeyType::Shard => vec!["shard_encryption".to_string(), "shard_authentication".to_string()],
            _ => vec![],
        };

        let key = HardwareSecurityKey {
            key_id,
            key_type,
            algorithm: algorithm.to_string(),
            key_size_bits: key_data.len() as u32 * 8,
            is_exportable,
            created_at,
            expires_at,
            permissions,
            usage_count: 0,
            last_used: 0,
        };

        // Log operation
        self.log_operation("import_key", key_id.clone(), key_data.to_vec(), Vec::new())?;

        Ok(key)
    }

    pub fn export_key(&self, key_id: &str) -> SecurityResult<Vec<u8>> {
        let module = self.module.lock().unwrap();

        // Validate key exists (simulated)
        if !self.key_exists(key_id)? {
            return Err(SecurityError::HardwareSecurityError(format!("Key {} not found", key_id)));
        }

        // Check if key is exportable
        let key = self.get_key_info(key_id)?;
        if !key.is_exportable {
            return Err(SecurityError::HardwareSecurityError(format!("Key {} is not exportable", key_id)));
        }

        // Simulate key export
        let key_data = Self::generate_random_key_data(key.key_size_bits as usize / 8);

        // Log operation
        self.log_operation("export_key", key_id.to_string(), Vec::new(), key_data.clone())?;

        Ok(key_data)
    }

    pub fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> SecurityResult<Vec<u8>> {
        let module = self.module.lock().unwrap();

        // Validate key exists (simulated)
        if !self.key_exists(key_id)? {
            return Err(SecurityError::HardwareSecurityError(format!("Key {} not found", key_id)));
        }

        // Check if key supports encryption
        let key = self.get_key_info(key_id)?;
        if !key.permissions.contains(&"encryption".to_string()) {
            return Err(SecurityError::HardwareSecurityError(format!("Key {} does not support encryption", key_id)));
        }

        // Simulate encryption
        let ciphertext = Self::simulate_encryption(plaintext);

        // Update key usage
        self.update_key_usage(key_id)?;

        // Log operation
        self.log_operation("encrypt", key_id.to_string(), plaintext.to_vec(), ciphertext.clone())?;

        Ok(ciphertext)
    }

    pub fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> SecurityResult<Vec<u8>> {
        let module = self.module.lock().unwrap();

        // Validate key exists (simulated)
        if !self.key_exists(key_id)? {
            return Err(SecurityError::HardwareSecurityError(format!("Key {} not found", key_id)));
        }

        // Check if key supports decryption
        let key = self.get_key_info(key_id)?;
        if !key.permissions.contains(&"encryption".to_string()) {
            return Err(SecurityError::HardwareSecurityError(format!("Key {} does not support decryption", key_id)));
        }

        // Simulate decryption
        let plaintext = Self::simulate_decryption(ciphertext);

        // Update key usage
        self.update_key_usage(key_id)?;

        // Log operation
        self.log_operation("decrypt", key_id.to_string(), ciphertext.to_vec(), plaintext.clone())?;

        Ok(plaintext)
    }

    pub fn sign(&self, key_id: &str, data: &[u8]) -> SecurityResult<Vec<u8>> {
        let module = self.module.lock().unwrap();

        // Validate key exists (simulated)
        if !self.key_exists(key_id)? {
            return Err(SecurityError::HardwareSecurityError(format!("Key {} not found", key_id)));
        }

        // Check if key supports signing
        let key = self.get_key_info(key_id)?;
        if !key.permissions.contains(&"signing".to_string()) {
            return Err(SecurityError::HardwareSecurityError(format!("Key {} does not support signing", key_id)));
        }

        // Simulate signing
        let signature = Self::simulate_signing(data);

        // Update key usage
        self.update_key_usage(key_id)?;

        // Log operation
        self.log_operation("sign", key_id.to_string(), data.to_vec(), signature.clone())?;

        Ok(signature)
    }

    pub fn verify(&self, key_id: &str, data: &[u8], signature: &[u8]) -> SecurityResult<bool> {
        let module = self.module.lock().unwrap();

        // Validate key exists (simulated)
        if !self.key_exists(key_id)? {
            return Err(SecurityError::HardwareSecurityError(format!("Key {} not found", key_id)));
        }

        // Check if key supports verification
        let key = self.get_key_info(key_id)?;
        if !key.permissions.contains(&"signing".to_string()) {
            return Err(SecurityError::HardwareSecurityError(format!("Key {} does not support verification", key_id)));
        }

        // Simulate verification
        let result = Self::simulate_verification(data, signature);

        // Update key usage
        self.update_key_usage(key_id)?;

        // Log operation
        self.log_operation("verify", key_id.to_string(), data.to_vec(), signature.to_vec())?;

        Ok(result)
    }

    pub fn get_key_info(&self, key_id: &str) -> SecurityResult<HardwareSecurityKey> {
        // Simulate key info retrieval
        let key = HardwareSecurityKey {
            key_id: key_id.to_string(),
            key_type: KeyType::Asymmetric,
            algorithm: "ed25519".to_string(),
            key_size_bits: 2048,
            is_exportable: true,
            created_at: Self::current_timestamp(),
            expires_at: Some(Self::current_timestamp() + (365 * 24 * 60 * 60)),
            permissions: vec!["encryption".to_string(), "signing".to_string()],
            usage_count: 100,
            last_used: Self::current_timestamp(),
        };

        Ok(key)
    }

    pub fn delete_key(&self, key_id: &str) -> SecurityResult<()> {
        // Simulate key deletion
        if !self.key_exists(key_id)? {
            return Err(SecurityError::HardwareSecurityError(format!("Key {} not found", key_id)));
        }

        // Log operation
        self.log_operation("delete_key", key_id.to_string(), Vec::new(), Vec::new())?;

        Ok(())
    }

    pub fn list_keys(&self) -> SecurityResult<Vec<HardwareSecurityKey>> {
        // Simulate key listing
        let keys = vec![
            HardwareSecurityKey {
                key_id: "test_key_1".to_string(),
                key_type: KeyType::Asymmetric,
                algorithm: "ed25519".to_string(),
                key_size_bits: 2048,
                is_exportable: true,
                created_at: Self::current_timestamp(),
                expires_at: Some(Self::current_timestamp() + (365 * 24 * 60 * 60)),
                permissions: vec!["encryption".to_string(), "signing".to_string()],
                usage_count: 100,
                last_used: Self::current_timestamp(),
            },
            HardwareSecurityKey {
                key_id: "test_key_2".to_string(),
                key_type: KeyType::Symmetric,
                algorithm: "aes256".to_string(),
                key_size_bits: 256,
                is_exportable: false,
                created_at: Self::current_timestamp(),
                expires_at: Some(Self::current_timestamp() + (30 * 24 * 60 * 60)),
                permissions: vec!["encryption".to_string()],
                usage_count: 50,
                last_used: Self::current_timestamp(),
            },
        ];

        Ok(keys)
    }

    pub fn get_status(&self) -> SecurityResult<HardwareSecurityStatus> {
        let module = self.module.lock().unwrap();
        Ok(module.status.clone())
    }

    pub fn get_capabilities(&self) -> SecurityResult<Vec<String>> {
        let module = self.module.lock().unwrap();
        Ok(module.capabilities.clone())
    }

    pub fn get_supported_algorithms(&self) -> SecurityResult<Vec<String>> {
        let module = self.module.lock().unwrap();
        Ok(module.supported_algorithms.clone())
    }

    fn key_exists(&self, key_id: &str) -> SecurityResult<bool> {
        // Simulate key existence check
        Ok(!key_id.is_empty()) // Always return true for simulation
    }

    fn update_key_usage(&self, key_id: &str) -> SecurityResult<()> {
        // Simulate key usage update
        Ok(())
    }

    fn log_operation(&self, operation: &str, key_id: String, input: Vec<u8>, output: Vec<u8>) -> SecurityResult<()> {
        let operation_id = format!("op_{}", Uuid::new_v4());
        let start_time = Self::current_timestamp();
        let end_time = start_time + 10; // Simulate 10ms operation
        let duration_ms = end_time - start_time;

        let operation = HardwareSecurityOperation {
            operation_id,
            operation_type: operation.to_string(),
            input_data: input,
            output_data: output,
            status: HardwareSecurityOperationStatus::Completed,
            start_time,
            end_time,
            duration_ms,
            error: None,
        };

        // Add to operation cache
        if self.config.cache_enabled {
            let mut cache = self.operation_cache.lock().unwrap();
            cache.insert(operation_id.clone(), operation.clone());
        }

        // Add to audit log
        if self.config.audit_enabled {
            let mut audit_log = self.audit_log.lock().unwrap();
            audit_log.push(operation);
        }

        Ok(())
    }

    fn simulate_encryption(plaintext: &[u8]) -> Vec<u8> {
        // Simple XOR encryption for simulation
        let key = b"hsm_simulation_key";
        plaintext.iter().zip(key.iter().cycle()).map(|(p, k)| p ^ k).collect()
    }

    fn simulate_decryption(ciphertext: &[u8]) -> Vec<u8> {
        // Simple XOR decryption for simulation
        let key = b"hsm_simulation_key";
        ciphertext.iter().zip(key.iter().cycle()).map(|(c, k)| c ^ k).collect()
    }

    fn simulate_signing(data: &[u8]) -> Vec<u8> {
        // Simple hash-based signature for simulation
        let hash = blake3::hash(data);
        hash.as_bytes().to_vec()
    }

    fn simulate_verification(data: &[u8], signature: &[u8]) -> bool {
        // Simple hash verification for simulation
        let hash = blake3::hash(data);
        hash.as_bytes() == signature
    }

    fn generate_random_key_data(size: usize) -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut data = vec![0u8; size];
        rng.fill(&mut data);
        data
    }

    fn current_timestamp() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardware_security_manager_creation() {
        let config = HardwareSecurityConfig::default();
        let manager = HardwareSecurityManager::new(config).unwrap();

        assert!(manager.module.lock().unwrap().is_available);
        assert_eq!(manager.module.lock().unwrap().status, HardwareSecurityStatus::Ready);
    }

    #[test]
    fn test_key_generation() {
        let config = HardwareSecurityConfig::default();
        let manager = HardwareSecurityManager::new(config).unwrap();

        let key = manager.generate_key(KeyType::Asymmetric, "ed25519", 2048).unwrap();

        assert!(!key.key_id.is_empty());
        assert_eq!(key.key_type, KeyType::Asymmetric);
        assert_eq!(key.algorithm, "ed25519");
        assert_eq!(key.key_size_bits, 2048);
        assert!(key.is_exportable);
        assert!(key.expires_at.is_some());
        assert!(key.permissions.contains(&"encryption".to_string()));
        assert!(key.permissions.contains(&"signing".to_string()));
    }

    #[test]
    fn test_key_import() {
        let config = HardwareSecurityConfig::default();
        let manager = HardwareSecurityManager::new(config).unwrap();

        let key_data = b"test_key_data";
        let key = manager.import_key(key_data, KeyType::Symmetric, "aes256").unwrap();

        assert!(!key.key_id.is_empty());
        assert_eq!(key.key_type, KeyType::Symmetric);
        assert_eq!(key.algorithm, "aes256");
        assert_eq!(key.key_size_bits, 96); // 12 bytes * 8
        assert!(!key.is_exportable);
        assert!(key.expires_at.is_some());
        assert!(key.permissions.contains(&"encryption".to_string()));
    }

    #[test]
    fn test_key_export() {
        let config = HardwareSecurityConfig::default();
        let manager = HardwareSecurityManager::new(config).unwrap();

        let key = manager.generate_key(KeyType::Asymmetric, "ed25519", 2048).unwrap();
        let exported = manager.export_key(&key.key_id).unwrap();

        assert!(!exported.is_empty());
        assert_eq!(exported.len(), 256); // 2048 bits / 8
    }

    #[test]
    fn test_encryption_decryption() {
        let config = HardwareSecurityConfig::default();
        let manager = HardwareSecurityManager::new(config).unwrap();

        let key = manager.generate_key(KeyType::Asymmetric, "ed25519", 2048).unwrap();
        let plaintext = b"This is a test message";

        let ciphertext = manager.encrypt(&key.key_id, plaintext).unwrap();
        let decrypted = manager.decrypt(&key.key_id, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_signing_verification() {
        let config = HardwareSecurityConfig::default();
        let manager = HardwareSecurityManager::new(config).unwrap();

        let key = manager.generate_key(KeyType::Asymmetric, "ed25519", 2048).unwrap();
        let data = b"This is some data to sign";

        let signature = manager.sign(&key.key_id, data).unwrap();
        let valid = manager.verify(&key.key_id, data, &signature).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_key_operations() {
        let config = HardwareSecurityConfig::default();
        let manager = HardwareSecurityManager::new(config).unwrap();

        // Generate key
        let key = manager.generate_key(KeyType::Asymmetric, "ed25519", 2048).unwrap();
        let key_id = key.key_id.clone();

        // Get key info
        let key_info = manager.get_key_info(&key_id).unwrap();
        assert_eq!(key_info.key_id, key_id);

        // List keys
        let keys = manager.list_keys().unwrap();
        assert!(keys.len() >= 1);

        // Delete key
        manager.delete_key(&key_id).unwrap();

        // Verify key is deleted
        let result = manager.get_key_info(&key_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_status_and_capabilities() {
        let config = HardwareSecurityConfig::default();
        let manager = HardwareSecurityManager::new(config).unwrap();

        let status = manager.get_status().unwrap();
        assert_eq!(status, HardwareSecurityStatus::Ready);

        let capabilities = manager.get_capabilities().unwrap();
        assert!(!capabilities.is_empty());

        let algorithms = manager.get_supported_algorithms().unwrap();
        assert!(!algorithms.is_empty());
    }

    #[test]
    fn test_operation_logging() {
        let config = HardwareSecurityConfig {
            audit_enabled: true,
            ..Default::default()
        };
        let manager = HardwareSecurityManager::new(config).unwrap();

        let key = manager.generate_key(KeyType::Asymmetric, "ed25519", 2048).unwrap();
        let _ciphertext = manager.encrypt(&key.key_id, b"test").unwrap();

        // Check audit log
        let audit_log = manager.audit_log.lock().unwrap();
        assert!(!audit_log.is_empty());
        assert_eq!(audit_log[0].operation_type, "generate_key");
        assert_eq!(audit_log[1].operation_type, "encrypt");
    }

    #[test]
    fn test_operation_cache() {
        let config = HardwareSecurityConfig {
            cache_enabled: true,
            ..Default::default()
        };
        let manager = HardwareSecurityManager::new(config).unwrap();

        let key = manager.generate_key(KeyType::Asymmetric, "ed25519", 2048).unwrap();
        let _ciphertext = manager.encrypt(&key.key_id, b"test").unwrap();

        // Check operation cache
        let operation_cache = manager.operation_cache.lock().unwrap();
        assert!(!operation_cache.is_empty());
        assert!(operation_cache.contains_key(&"generate_key".to_string()));
        assert!(operation_cache.contains_key(&"encrypt".to_string()));
    }

    #[test]
    fn test_invalid_operations() {
        let config = HardwareSecurityConfig::default();
        let manager = HardwareSecurityManager::new(config).unwrap();

        // Test invalid key operations
        let result = manager.encrypt("invalid_key", b"test");
        assert!(result.is_err());

        let result = manager.decrypt("invalid_key", b"ciphertext");
        assert!(result.is_err());

        let result = manager.sign("invalid_key", b"data");
        assert!(result.is_err());

        let result = manager.verify("invalid_key", b"data", b"signature");
        assert!(result.is_err());
    }

    #[test]
    fn test_algorithm_validation() {
        let config = HardwareSecurityConfig::default();
        let manager = HardwareSecurityManager::new(config).unwrap();

        // Test unsupported algorithm
        let result = manager.generate_key(KeyType::Asymmetric, "unsupported_algorithm", 2048);
        assert!(result.is_err());

        // Test invalid key size
        let result = manager.generate_key(KeyType::Asymmetric, "ed25519", 8192);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_type_permissions() {
        let config = HardwareSecurityConfig::default();
        let manager = HardwareSecurityManager::new(config).unwrap();

        // Test root key permissions
        let root_key = manager.generate_key(KeyType::Root, "ed25519", 2048).unwrap();
        assert!(root_key.permissions.contains(&"root_access".to_string()));
        assert!(root_key.permissions.contains(&"full_control".to_string()));

        // Test node key permissions
        let node_key = manager.generate_key(KeyType::Node, "ed25519", 2048).unwrap();
        assert!(node_key.permissions.contains(&"node_authentication".to_string()));
        assert!(node_key.permissions.contains(&"node_communication".to_string()));

        // Test shard key permissions
        let shard_key = manager.generate_key(KeyType::Shard, "ed25519", 2048).unwrap();
        assert!(shard_key.permissions.contains(&"shard_encryption".to_string()));
        assert!(shard_key.permissions.contains(&"shard_authentication".to_string()));
    }

    #[test]
    fn test_key_expiration() {
        let config = HardwareSecurityConfig::default();
        let manager = HardwareSecurityManager::new(config).unwrap();

        let key = manager.generate_key(KeyType::Asymmetric, "ed25519", 2048).unwrap();
        assert!(key.expires_at.is_some());
        assert!(key.expires_at.unwrap() > key.created_at);
    }

    #[test]
    fn test_export_restriction() {
        let config = HardwareSecurityConfig::default();
        let manager = HardwareSecurityManager::new(config).unwrap();

        // Test exportable key
        let exportable_key = manager.generate_key(KeyType::Asymmetric, "ed25519", 2048).unwrap();
        let exported = manager.export_key(&exportable_key.key_id).unwrap();
        assert!(!exported.is_empty());

        // Test non-exportable key
        let non_exportable_key = manager.generate_key(KeyType::Symmetric, "aes256", 256).unwrap();
        let result = manager.export_key(&non_exportable_key.key_id);
        assert!(result.is_err());
    }
}