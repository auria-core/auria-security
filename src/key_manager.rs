// File: key_manager.rs - This file is part of AURIA
// Copyright (c) 2026 AURIA Developers and Contributors
// Description:
//     Key management system for AURIA Runtime Core.
//     Provides secure storage, rotation, and management of cryptographic keys.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyStore {
    pub keys: HashMap<String, KeyEntry>,
    pub config: KeyStoreConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    pub key_id: String,
    pub key_type: KeyType,
    pub public_key: String,
    pub private_key: Option<String>,
    pub algorithm: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub permissions: Vec<String>,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[repr(u8)]
pub enum KeyType {
    Asymmetric = 0,
    Symmetric = 1,
    Ephemeral = 2,
    Root = 3,
    Node = 4,
    Shard = 5,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyStoreConfig {
    pub store_path: String,
    pub encryption_enabled: bool,
    pub auto_rotate: bool,
    pub rotation_interval_days: u32,
    pub backup_enabled: bool,
    pub backup_path: String,
    pub backup_interval_hours: u32,
}

impl Default for KeyStoreConfig {
    fn default() -> Self {
        Self {
            store_path: "./keys/keystore.json".to_string(),
            encryption_enabled: true,
            auto_rotate: true,
            rotation_interval_days: 30,
            backup_enabled: true,
            backup_path: "./keys/backup/".to_string(),
            backup_interval_hours: 24,
        }
    }
}

impl KeyStore {
    pub fn new(config: KeyStoreConfig) -> SecurityResult<Self> {
        let store_path = Path::new(&config.store_path);

        if store_path.exists() {
            let content = std::fs::read_to_string(store_path)
                .map_err(|e| SecurityError::KeyManagementError(format!("Failed to read keystore: {}", e)))?;
            let keys: KeyStore = serde_json::from_str(&content)
                .map_err(|e| SecurityError::KeyManagementError(format!("Failed to parse keystore: {}", e)))?;
            Ok(keys)
        } else {
            Ok(Self {
                keys: HashMap::new(),
                config,
            })
        }
    }

    pub fn add_key(&mut self, key_entry: KeyEntry) -> SecurityResult<String> {
        if self.keys.contains_key(&key_entry.key_id) {
            return Err(SecurityError::KeyAlreadyExists(key_entry.key_id.clone()));
        }

        self.keys.insert(key_entry.key_id.clone(), key_entry);
        self.save()?;
        Ok(key_entry.key_id.clone())
    }

    pub fn get_key(&self, key_id: &str) -> SecurityResult<KeyEntry> {
        self.keys.get(key_id)
            .cloned()
            .ok_or(SecurityError::KeyNotFound(key_id.to_string()))
    }

    pub fn get_public_key(&self, key_id: &str) -> SecurityResult<String> {
        self.get_key(key_id)
            .map(|entry| entry.public_key)
    }

    pub fn get_private_key(&self, key_id: &str) -> SecurityResult<String> {
        self.get_key(key_id)
            .and_then(|entry| entry.private_key.ok_or(SecurityError::KeyManagementError("Private key not available".to_string())))
    }

    pub fn remove_key(&mut self, key_id: &str) -> SecurityResult<() > {
        if self.keys.remove(key_id).is_some() {
            self.save()?;
            Ok(())
        } else {
            Err(SecurityError::KeyNotFound(key_id.to_string()))
        }
    }

    pub fn rotate_key(&mut self, key_id: &str) -> SecurityResult<String> {
        let old_key = self.get_key(key_id)?;

        // Generate new key
        let new_key_entry = self.generate_new_key_entry(&old_key)?;

        // Add new key
        self.add_key(new_key_entry.clone())?;

        // Remove old key if not root key
        if old_key.key_type != KeyType::Root {
            self.remove_key(key_id)?;
        }

        Ok(new_key_entry.key_id)
    }

    pub fn list_keys(&self) -> Vec<KeyEntry> {
        self.keys.values().cloned().collect()
    }

    pub fn list_keys_by_type(&self, key_type: KeyType) -> Vec<KeyEntry> {
        self.keys.values()
            .filter(|entry| entry.key_type == key_type)
            .cloned()
            .collect()
    }

    pub fn search_keys(&self, query: &str) -> Vec<KeyEntry> {
        self.keys.values()
            .filter(|entry| {
                entry.key_id.contains(query) ||
                entry.tags.iter().any(|tag| tag.contains(query)) ||
                entry.metadata.values().any(|val| val.contains(query))
            })
            .cloned()
            .collect()
    }

    pub fn backup_keys(&self) -> SecurityResult<() > {
        if !self.config.backup_enabled {
            return Err(SecurityError::KeyManagementError("Backups not enabled".to_string()));
        }

        let backup_path = Path::new(&self.config.backup_path);
        std::fs::create_dir_all(backup_path)
            .map_err(|e| SecurityError::KeyManagementError(format!("Failed to create backup directory: {}", e)))?;

        let timestamp = Self::current_timestamp();
        let backup_file = backup_path.join(format!("keystore_backup_{}.json", timestamp));

        let content = serde_json::to_string_pretty(self)
            .map_err(|e| SecurityError::KeyManagementError(format!("Failed to serialize keystore: {}", e)))?;

        std::fs::write(&backup_file, content)
            .map_err(|e| SecurityError::KeyManagementError(format!("Failed to write backup file: {}", e)))?;

        Ok(())
    }

    pub fn restore_backup(&mut self, backup_file: &str) -> SecurityResult<() > {
        let content = std::fs::read_to_string(backup_file)
            .map_err(|e| SecurityError::KeyManagementError(format!("Failed to read backup file: {}", e)))?;

        let backup_keys: KeyStore = serde_json::from_str(&content)
            .map_err(|e| SecurityError::KeyManagementError(format!("Failed to parse backup file: {}", e)))?;

        self.keys = backup_keys.keys;
        self.save()?;

        Ok(())
    }

    pub fn check_expired_keys(&mut self) -> Vec<String> {
        let current_time = Self::current_timestamp();
        let mut expired_keys = Vec::new();

        for (key_id, entry) in &self.keys {
            if let Some(expires_at) = entry.expires_at {
                if current_time > expires_at {
                    expired_keys.push(key_id.clone());
                }
            }
        }

        // Remove expired keys
        for key_id in &expired_keys {
            self.keys.remove(key_id);
        }

        // Save changes
        if !expired_keys.is_empty() {
            self.save().ok();
        }

        expired_keys
    }

    pub fn generate_new_key_entry(&self, template: &KeyEntry) -> SecurityResult<KeyEntry> {
        let key_id = format!("key_{}", Uuid::new_v4());
        let created_at = Self::current_timestamp();
        let expires_at = if template.key_type == KeyType::Root {
            None // Root keys don't expire
        } else {
            Some(created_at + (self.config.rotation_interval_days * 24 * 60 * 60))
        };

        // Generate new key pair
        let keypair = crypto::generate_keypair()?;

        Ok(KeyEntry {
            key_id,
            key_type: template.key_type,
            public_key: keypair.public.to_hex(),
            private_key: Some(keypair.private.to_hex()),
            algorithm: "ed25519".to_string(),
            created_at,
            expires_at,
            permissions: template.permissions.clone(),
            tags: template.tags.clone(),
            metadata: template.metadata.clone(),
        })
    }

    fn save(&self) -> SecurityResult<() > {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| SecurityError::KeyManagementError(format!("Failed to serialize keystore: {}", e)))?;

        let store_path = Path::new(&self.config.store_path);

        // Create directory if it doesn't exist
        if let Some(parent) = store_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| SecurityError::KeyManagementError(format!("Failed to create keystore directory: {}", e)))?;
        }

        std::fs::write(store_path, content)
            .map_err(|e| SecurityError::KeyManagementError(format!("Failed to write keystore: {}", e)))?;

        Ok(())
    }

    fn current_timestamp() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}

#[derive(Debug, Clone)]
pub struct KeyManager {
    store: Arc<RwLock<KeyStore>>,
}

impl KeyManager {
    pub fn new(config: KeyStoreConfig) -> SecurityResult<Self> {
        let store = KeyStore::new(config)?;
        Ok(Self {
            store: Arc::new(RwLock::new(store)),
        })
    }

    pub fn add_key(&self, key_entry: KeyEntry) -> SecurityResult<String> {
        let mut store = self.store.write().unwrap();
        store.add_key(key_entry)
    }

    pub fn get_key(&self, key_id: &str) -> SecurityResult<KeyEntry> {
        let store = self.store.read().unwrap();
        store.get_key(key_id)
    }

    pub fn get_public_key(&self, key_id: &str) -> SecurityResult<String> {
        let store = self.store.read().unwrap();
        store.get_public_key(key_id)
    }

    pub fn get_private_key(&self, key_id: &str) -> SecurityResult<String> {
        let store = self.store.read().unwrap();
        store.get_private_key(key_id)
    }

    pub fn remove_key(&self, key_id: &str) -> SecurityResult<() > {
        let mut store = self.store.write().unwrap();
        store.remove_key(key_id)
    }

    pub fn rotate_key(&self, key_id: &str) -> SecurityResult<String> {
        let mut store = self.store.write().unwrap();
        store.rotate_key(key_id)
    }

    pub fn list_keys(&self) -> Vec<KeyEntry> {
        let store = self.store.read().unwrap();
        store.list_keys()
    }

    pub fn list_keys_by_type(&self, key_type: KeyType) -> Vec<KeyEntry> {
        let store = self.store.read().unwrap();
        store.list_keys_by_type(key_type)
    }

    pub fn search_keys(&self, query: &str) -> Vec<KeyEntry> {
        let store = self.store.read().unwrap();
        store.search_keys(query)
    }

    pub fn backup_keys(&self) -> SecurityResult<() > {
        let store = self.store.read().unwrap();
        store.backup_keys()
    }

    pub fn restore_backup(&self, backup_file: &str) -> SecurityResult<() > {
        let mut store = self.store.write().unwrap();
        store.restore_backup(backup_file)
    }

    pub fn check_expired_keys(&self) -> Vec<String> {
        let mut store = self.store.write().unwrap();
        store.check_expired_keys()
    }

    pub fn generate_node_key(&self, node_id: &str) -> SecurityResult<KeyEntry> {
        let mut store = self.store.write().unwrap();

        // Create template from existing node keys
        let template = KeyEntry {
            key_id: "template_node_key".to_string(),
            key_type: KeyType::Node,
            public_key: "".to_string(),
            private_key: None,
            algorithm: "ed25519".to_string(),
            created_at: 0,
            expires_at: Some(Self::current_timestamp() + (365 * 24 * 60 * 60)), // 1 year
            permissions: vec!["node_authentication".to_string(), "node_communication".to_string()],
            tags: vec!["node".to_string(), node_id.to_string()],
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("node_id".to_string(), node_id.to_string());
                meta.insert("purpose".to_string(), "node_authentication".to_string());
                meta
            },
        };

        let new_key = store.generate_new_key_entry(&template)?;
        store.add_key(new_key.clone())?;

        Ok(new_key)
    }

    pub fn generate_shard_key(&self, shard_id: &str) -> SecurityResult<KeyEntry> {
        let mut store = self.store.write().unwrap();

        // Create template from existing shard keys
        let template = KeyEntry {
            key_id: "template_shard_key".to_string(),
            key_type: KeyType::Shard,
            public_key: "".to_string(),
            private_key: None,
            algorithm: "ed25519".to_string(),
            created_at: 0,
            expires_at: Some(Self::current_timestamp() + (7 * 24 * 60 * 60)), // 1 week
            permissions: vec!["shard_encryption".to_string(), "shard_authentication".to_string()],
            tags: vec!["shard".to_string(), shard_id.to_string()],
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("shard_id".to_string(), shard_id.to_string());
                meta.insert("purpose".to_string(), "shard_encryption".to_string());
                meta
            },
        };

        let new_key = store.generate_new_key_entry(&template)?;
        store.add_key(new_key.clone())?;

        Ok(new_key)
    }

    fn current_timestamp() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_key_store_creation() {
        let config = KeyStoreConfig::default();
        let mut store = KeyStore::new(config).unwrap();

        assert!(store.keys.is_empty());
        assert_eq!(store.config.store_path, "./keys/keystore.json");
    }

    #[test]
    fn test_key_addition() {
        let config = KeyStoreConfig {
            store_path: "./test_keys/keystore.json".to_string(),
            ..Default::default()
        };

        let mut store = KeyStore::new(config).unwrap();

        let key_entry = KeyEntry {
            key_id: "test_key_1".to_string(),
            key_type: KeyType::Asymmetric,
            public_key: "test_public_key".to_string(),
            private_key: Some("test_private_key".to_string()),
            algorithm: "ed25519".to_string(),
            created_at: 12345,
            expires_at: Some(67890),
            permissions: vec!["test_permission".to_string()],
            tags: vec!["test".to_string()],
            metadata: HashMap::new(),
        };

        let key_id = store.add_key(key_entry).unwrap();
        assert_eq!(key_id, "test_key_1");
        assert_eq!(store.keys.len(), 1);
    }

    #[test]
    fn test_key_retrieval() {
        let config = KeyStoreConfig {
            store_path: "./test_keys/keystore.json".to_string(),
            ..Default::default()
        };

        let mut store = KeyStore::new(config).unwrap();

        let key_entry = KeyEntry {
            key_id: "test_key_1".to_string(),
            key_type: KeyType::Asymmetric,
            public_key: "test_public_key".to_string(),
            private_key: Some("test_private_key".to_string()),
            algorithm: "ed25519".to_string(),
            created_at: 12345,
            expires_at: Some(67890),
            permissions: vec!["test_permission".to_string()],
            tags: vec!["test".to_string()],
            metadata: HashMap::new(),
        };

        store.add_key(key_entry.clone()).unwrap();

        let retrieved = store.get_key("test_key_1").unwrap();
        assert_eq!(retrieved.key_id, "test_key_1");
        assert_eq!(retrieved.public_key, "test_public_key");
    }

    #[test]
    fn test_key_removal() {
        let config = KeyStoreConfig {
            store_path: "./test_keys/keystore.json".to_string(),
            ..Default::default()
        };

        let mut store = KeyStore::new(config).unwrap();

        let key_entry = KeyEntry {
            key_id: "test_key_1".to_string(),
            key_type: KeyType::Asymmetric,
            public_key: "test_public_key".to_string(),
            private_key: Some("test_private_key".to_string()),
            algorithm: "ed25519".to_string(),
            created_at: 12345,
            expires_at: Some(67890),
            permissions: vec!["test_permission".to_string()],
            tags: vec!["test".to_string()],
            metadata: HashMap::new(),
        };

        store.add_key(key_entry).unwrap();
        assert_eq!(store.keys.len(), 1);

        store.remove_key("test_key_1").unwrap();
        assert_eq!(store.keys.len(), 0);
    }

    #[test]
    fn test_key_rotation() {
        let config = KeyStoreConfig {
            store_path: "./test_keys/keystore.json".to_string(),
            rotation_interval_days: 1,
            ..Default::default()
        };

        let mut store = KeyStore::new(config).unwrap();

        let key_entry = KeyEntry {
            key_id: "test_key_1".to_string(),
            key_type: KeyType::Asymmetric,
            public_key: "test_public_key".to_string(),
            private_key: Some("test_private_key".to_string()),
            algorithm: "ed25519".to_string(),
            created_at: 12345,
            expires_at: Some(67890),
            permissions: vec!["test_permission".to_string()],
            tags: vec!["test".to_string()],
            metadata: HashMap::new(),
        };

        store.add_key(key_entry).unwrap();

        let new_key_id = store.rotate_key("test_key_1").unwrap();
        assert_ne!(new_key_id, "test_key_1");
        assert_eq!(store.keys.len(), 2); // Old and new key
    }

    #[test]
    fn test_key_search() {
        let config = KeyStoreConfig {
            store_path: "./test_keys/keystore.json".to_string(),
            ..Default::default()
        };

        let mut store = KeyStore::new(config).unwrap();

        let key1 = KeyEntry {
            key_id: "test_key_1".to_string(),
            key_type: KeyType::Asymmetric,
            public_key: "test_public_key".to_string(),
            private_key: Some("test_private_key".to_string()),
            algorithm: "ed25519".to_string(),
            created_at: 12345,
            expires_at: Some(67890),
            permissions: vec!["test_permission".to_string()],
            tags: vec!["test".to_string(), "searchable".to_string()],
            metadata: HashMap::new(),
        };

        let key2 = KeyEntry {
            key_id: "another_key".to_string(),
            key_type: KeyType::Symmetric,
            public_key: "another_public".to_string(),
            private_key: Some("another_private".to_string()),
            algorithm: "aes256".to_string(),
            created_at: 12345,
            expires_at: Some(67890),
            permissions: vec!["another_permission".to_string()],
            tags: vec!["another".to_string()],
            metadata: HashMap::new(),
        };

        store.add_key(key1).unwrap();
        store.add_key(key2).unwrap();

        let results = store.search_keys("test");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].key_id, "test_key_1");

        let results = store.search_keys("another");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].key_id, "another_key");
    }

    #[test]
    fn test_backup_restore() {
        let config = KeyStoreConfig {
            store_path: "./test_keys/keystore.json".to_string(),
            backup_path: "./test_keys/backup/".to_string(),
            ..Default::default()
        };

        let mut store = KeyStore::new(config).unwrap();

        let key_entry = KeyEntry {
            key_id: "test_key_1".to_string(),
            key_type: KeyType::Asymmetric,
            public_key: "test_public_key".to_string(),
            private_key: Some("test_private_key".to_string()),
            algorithm: "ed25519".to_string(),
            created_at: 12345,
            expires_at: Some(67890),
            permissions: vec!["test_permission".to_string()],
            tags: vec!["test".to_string()],
            metadata: HashMap::new(),
        };

        store.add_key(key_entry).unwrap();

        // Create backup
        store.backup_keys().unwrap();

        // Create new empty store
        let mut new_store = KeyStore::new(config.clone()).unwrap();
        assert!(new_store.keys.is_empty());

        // Restore from backup
        new_store.restore_backup("./test_keys/backup/keystore_backup_*.json").unwrap();
        assert_eq!(new_store.keys.len(), 1);
    }

    #[test]
    fn test_expired_keys() {
        let config = KeyStoreConfig {
            store_path: "./test_keys/keystore.json".to_string(),
            ..Default::default()
        };

        let mut store = KeyStore::new(config).unwrap();

        let expired_key = KeyEntry {
            key_id: "expired_key".to_string(),
            key_type: KeyType::Asymmetric,
            public_key: "expired_public".to_string(),
            private_key: Some("expired_private".to_string()),
            algorithm: "ed25519".to_string(),
            created_at: 1000,
            expires_at: Some(2000), // Expired
            permissions: vec!["expired_permission".to_string()],
            tags: vec!["expired".to_string()],
            metadata: HashMap::new(),
        };

        let valid_key = KeyEntry {
            key_id: "valid_key".to_string(),
            key_type: KeyType::Asymmetric,
            public_key: "valid_public".to_string(),
            private_key: Some("valid_private".to_string()),
            algorithm: "ed25519".to_string(),
            created_at: 3000,
            expires_at: Some(4000), // Valid
            permissions: vec!["valid_permission".to_string()],
            tags: vec!["valid".to_string()],
            metadata: HashMap::new(),
        };

        store.add_key(expired_key).unwrap();
        store.add_key(valid_key).unwrap();

        let expired = store.check_expired_keys();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], "expired_key");
        assert_eq!(store.keys.len(), 1); // Only valid key remains
    }

    #[test]
    fn test_node_key_generation() {
        let config = KeyStoreConfig {
            store_path: "./test_keys/keystore.json".to_string(),
            ..Default::default()
        };

        let mut store = KeyStore::new(config).unwrap();
        let key_manager = KeyManager::new(config).unwrap();

        let node_key = key_manager.generate_node_key("test_node").unwrap();

        assert_eq!(node_key.key_type, KeyType::Node);
        assert!(node_key.expires_at.is_some());
        assert!(node_key.expires_at.unwrap() > node_key.created_at);
        assert!(node_key.permissions.contains(&"node_authentication".to_string()));
        assert!(node_key.tags.contains(&"node".to_string()));
        assert!(node_key.tags.contains(&"test_node".to_string()));
    }

    #[test]
    fn test_shard_key_generation() {
        let config = KeyStoreConfig {
            store_path: "./test_keys/keystore.json".to_string(),
            ..Default::default()
        };

        let mut store = KeyStore::new(config).unwrap();
        let key_manager = KeyManager::new(config).unwrap();

        let shard_key = key_manager.generate_shard_key("test_shard").unwrap();

        assert_eq!(shard_key.key_type, KeyType::Shard);
        assert!(shard_key.expires_at.is_some());
        assert!(shard_key.expires_at.unwrap() > shard_key.created_at);
        assert!(shard_key.permissions.contains(&"shard_encryption".to_string()));
        assert!(shard_key.tags.contains(&"shard".to_string()));
        assert!(shard_key.tags.contains(&"test_shard".to_string()));
    }

    #[test]
    fn test_key_manager_operations() {
        let config = KeyStoreConfig {
            store_path: "./test_keys/keystore.json".to_string(),
            ..Default::default()
        };

        let key_manager = KeyManager::new(config).unwrap();

        // Generate node key
        let node_key = key_manager.generate_node_key("test_node").unwrap();
        let key_id = node_key.key_id.clone();

        // List keys
        let keys = key_manager.list_keys();
        assert_eq!(keys.len(), 1);

        // Get key
        let retrieved = key_manager.get_key(&key_id).unwrap();
        assert_eq!(retrieved.key_id, key_id);

        // Rotate key
        let new_key_id = key_manager.rotate_key(&key_id).unwrap();
        assert_ne!(new_key_id, key_id);

        // Remove key
        key_manager.remove_key(&new_key_id).unwrap();
        let keys = key_manager.list_keys();
        assert_eq!(keys.len(), 0);
    }

    #[test]
    fn test_cleanup() {
        // Clean up test files
        let _ = fs::remove_dir_all("./test_keys");
    }
}