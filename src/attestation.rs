// File: attestation.rs - This file is part of AURIA
// Copyright (c) 2026 AURIA Developers and Contributors
// Description:
//     Attestation system for AURIA Runtime Core.
//     Provides hardware and software attestation to verify node integrity and security.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub attestation_id: String,
    pub node_id: String,
    pub hardware_info: HardwareInfo,
    pub software_info: SoftwareInfo,
    pub security_state: SecurityState,
    pub timestamp: u64,
    pub expiration: u64,
    pub signatures: HashMap<String, Signature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareInfo {
    pub cpu_info: CpuInfo,
    pub memory_info: MemoryInfo,
    pub storage_info: StorageInfo,
    pub network_info: NetworkInfo,
    pub security_features: SecurityFeatures,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuInfo {
    pub vendor: String,
    pub model: String,
    pub cores: u32,
    pub threads: u32,
    pub architecture: String,
    pub flags: Vec<String>,
    pub trusted_execution: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInfo {
    pub total_memory_bytes: u64,
    pub available_memory_bytes: u64,
    pub memory_speed_mhz: u32,
    pub memory_type: String,
    pub ecc_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageInfo {
    pub total_storage_bytes: u64,
    pub available_storage_bytes: u64,
    pub storage_type: String,
    pub encryption_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub mac_address: String,
    pub ip_addresses: Vec<String>,
    pub network_speed_mbps: u32,
    pub trusted_network: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFeatures {
    pub trusted_execution_supported: bool,
    pub secure_boot_enabled: bool,
    pub tpm_available: bool,
    pub virtualization_enabled: bool,
    pub firewall_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareInfo {
    pub os_info: OsInfo,
    pub kernel_info: KernelInfo,
    pub runtime_info: RuntimeInfo,
    pub security_patches: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub kernel_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelInfo {
    pub version: String,
    pub security_patches: Vec<String>,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeInfo {
    pub auria_version: String,
    pub rust_version: String,
    pub features: Vec<String>,
    pub build_info: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityState {
    pub security_level: SecurityLevel,
    pub vulnerabilities: Vec<String>,
    pub compliance_status: ComplianceStatus,
    pub last_security_scan: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(u8)]
pub enum SecurityLevel {
    Unknown = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(u8)]
pub enum ComplianceStatus {
    Unknown = 0,
    NonCompliant = 1,
    PartiallyCompliant = 2,
    Compliant = 3,
    Certified = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResult {
    pub attestation_id: String,
    pub node_id: String,
    pub status: AttestationStatus,
    pub verification_results: Vec<VerificationResult>,
    pub overall_score: f32,
    pub recommendations: Vec<String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(u8)]
pub enum AttestationStatus {
    Pending = 0,
    Processing = 1,
    Valid = 2,
    Invalid = 3,
    Expired = 4,
    Revoked = 5,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub component: String,
    pub status: VerificationStatus,
    pub details: String,
    pub score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(u8)]
pub enum VerificationStatus {
    Unknown = 0,
    Passed = 1,
    Failed = 2,
    Warning = 3,
    Skipped = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationRequest {
    pub node_id: String,
    pub requested_info: Vec<String>,
    pub nonce: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResponse {
    pub attestation_id: String,
    pub node_id: String,
    pub attestation: Attestation,
    pub signature: Signature,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationPolicy {
    pub minimum_security_level: SecurityLevel,
    pub required_compliance_status: ComplianceStatus,
    pub required_features: Vec<String>,
    pub expiration_days: u32,
    pub renewal_policy: RenewalPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(u8)]
pub enum RenewalPolicy {
    Auto = 0,
    Manual = 1,
    Never = 2,
}

impl Attestation {
    pub fn new(node_id: &str, security_config: &SecurityConfig) -> SecurityResult<Self> {
        let hardware_info = HardwareInfo::collect()?;
        let software_info = SoftwareInfo::collect()?;
        let security_state = SecurityState::evaluate(&hardware_info, &software_info, security_config)?;

        let attestation_id = format!("attestation_{}", Uuid::new_v4());
        let timestamp = Self::current_timestamp();
        let expiration = timestamp + (30 * 24 * 60 * 60); // 30 days

        Ok(Self {
            attestation_id,
            node_id: node_id.to_string(),
            hardware_info,
            software_info,
            security_state,
            timestamp,
            expiration,
            signatures: HashMap::new(),
        })
    }

    pub fn is_valid(&self) -> bool {
        let current_time = Self::current_timestamp();
        current_time < self.expiration && self.security_state.security_level >= SecurityLevel::Medium
    }

    pub fn add_signature(&mut self, signer: &str, signature: Signature) {
        self.signatures.insert(signer.to_string(), signature);
    }

    pub fn verify_signatures(&self, public_keys: &HashMap<String, PublicKey>) -> SecurityResult<bool> {
        for (signer, signature) in &self.signatures {
            if let Some(public_key) = public_keys.get(signer) {
                let data = serde_json::to_vec(self)
                    .map_err(|_| SecurityError::SerializationError("Failed to serialize attestation".to_string()))?;
                if !crypto::verify_signature(public_key, &data, signature)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn current_timestamp() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}

impl HardwareInfo {
    pub fn collect() -> SecurityResult<Self> {
        // This would collect actual hardware information
        // For now, we'll return mock data
        Ok(Self {
            cpu_info: CpuInfo {
                vendor: "Intel".to_string(),
                model: "Core i7-9700K".to_string(),
                cores: 8,
                threads: 8,
                architecture: "x86_64".to_string(),
                flags: vec!["sse4_2".to_string(), "avx2".to_string()],
                trusted_execution: true,
            },
            memory_info: MemoryInfo {
                total_memory_bytes: 16 * 1024 * 1024 * 1024,
                available_memory_bytes: 8 * 1024 * 1024 * 1024,
                memory_speed_mhz: 3200,
                memory_type: "DDR4".to_string(),
                ecc_enabled: false,
            },
            storage_info: StorageInfo {
                total_storage_bytes: 512 * 1024 * 1024 * 1024,
                available_storage_bytes: 256 * 1024 * 1024 * 1024,
                storage_type: "NVMe SSD".to_string(),
                encryption_enabled: true,
            },
            network_info: NetworkInfo {
                mac_address: "00:11:22:33:44:55".to_string(),
                ip_addresses: vec!["192.168.1.100".to_string()],
                network_speed_mbps: 1000,
                trusted_network: true,
            },
            security_features: SecurityFeatures {
                trusted_execution_supported: true,
                secure_boot_enabled: true,
                tpm_available: true,
                virtualization_enabled: true,
                firewall_enabled: true,
            },
        })
    }
}

impl SoftwareInfo {
    pub fn collect() -> SecurityResult<Self> {
        // This would collect actual software information
        // For now, we'll return mock data
        Ok(Self {
            os_info: OsInfo {
                name: "Linux".to_string(),
                version: "5.15.0-76-generic".to_string(),
                architecture: "x86_64".to_string(),
                kernel_version: "5.15.0-76-generic".to_string(),
            },
            kernel_info: KernelInfo {
                version: "5.15.0-76-generic".to_string(),
                security_patches: vec!["CVE-2023-1234".to_string()],
                capabilities: vec!["seccomp".to_string(), "apparmor".to_string()],
            },
            runtime_info: RuntimeInfo {
                auria_version: "1.0.0".to_string(),
                rust_version: "1.70.0".to_string(),
                features: vec!["crypto".to_string(), "attestation".to_string()],
                build_info: "debug".to_string(),
            },
            security_patches: vec!["2023-001".to_string()],
        })
    }
}

impl SecurityState {
    pub fn evaluate(
        hardware_info: &HardwareInfo,
        software_info: &SoftwareInfo,
        security_config: &SecurityConfig,
    ) -> SecurityResult<Self> {
        let security_level = Self::calculate_security_level(hardware_info, software_info);
        let vulnerabilities = Self::identify_vulnerabilities(hardware_info, software_info);
        let compliance_status = Self::check_compliance(hardware_info, software_info, security_config);
        let last_security_scan = Attestation::current_timestamp();

        Ok(Self {
            security_level,
            vulnerabilities,
            compliance_status,
            last_security_scan,
        })
    }

    fn calculate_security_level(
        hardware_info: &HardwareInfo,
        software_info: &SoftwareInfo,
    ) -> SecurityLevel {
        let mut score = 0.0;

        // Hardware security features
        if hardware_info.security_features.trusted_execution_supported {
            score += 20.0;
        }
        if hardware_info.security_features.secure_boot_enabled {
            score += 15.0;
        }
        if hardware_info.security_features.tpm_available {
            score += 15.0;
        }

        // Software security features
        if software_info.kernel_info.capabilities.contains(&"seccomp".to_string()) {
            score += 10.0;
        }
        if software_info.kernel_info.capabilities.contains(&"apparmor".to_string()) {
            score += 10.0;
        }
        if software_info.runtime_info.features.contains(&"crypto".to_string()) {
            score += 10.0;
        }

        // Performance and memory security
        if hardware_info.memory_info.ecc_enabled {
            score += 10.0;
        }
        if hardware_info.storage_info.encryption_enabled {
            score += 10.0;
        }

        if score >= 80.0 {
            SecurityLevel::Critical
        } else if score >= 60.0 {
            SecurityLevel::High
        } else if score >= 40.0 {
            SecurityLevel::Medium
        } else if score >= 20.0 {
            SecurityLevel::Low
        } else {
            SecurityLevel::Unknown
        }
    }

    fn identify_vulnerabilities(
        hardware_info: &HardwareInfo,
        software_info: &SoftwareInfo,
    ) -> Vec<String> {
        let mut vulnerabilities = Vec::new();

        // Check for known vulnerabilities
        if !hardware_info.security_features.trusted_execution_supported {
            vulnerabilities.push("Trusted execution not supported".to_string());
        }
        if !hardware_info.security_features.secure_boot_enabled {
            vulnerabilities.push("Secure boot disabled".to_string());
        }
        if !hardware_info.security_features.tpm_available {
            vulnerabilities.push("TPM not available".to_string());
        }

        // Check software vulnerabilities
        if software_info.security_patches.is_empty() {
            vulnerabilities.push("No security patches applied".to_string());
        }

        vulnerabilities
    }

    fn check_compliance(
        hardware_info: &HardwareInfo,
        software_info: &SoftwareInfo,
        security_config: &SecurityConfig,
    ) -> ComplianceStatus {
        let mut compliance_score = 0.0;

        // Check hardware compliance
        if hardware_info.security_features.trusted_execution_supported {
            compliance_score += 25.0;
        }
        if hardware_info.security_features.secure_boot_enabled {
            compliance_score += 25.0;
        }
        if hardware_info.security_features.tpm_available {
            compliance_score += 25.0;
        }

        // Check software compliance
        if software_info.runtime_info.features.contains(&"crypto".to_string()) {
            compliance_score += 25.0;
        }

        if compliance_score >= 75.0 {
            ComplianceStatus::Certified
        } else if compliance_score >= 50.0 {
            ComplianceStatus::Compliant
        } else if compliance_score >= 25.0 {
            ComplianceStatus::PartiallyCompliant
        } else {
            ComplianceStatus::NonCompliant
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_creation() {
        let security_config = SecurityConfig::default();
        let attestation = Attestation::new("node_123", &security_config).unwrap();

        assert!(!attestation.attestation_id.is_empty());
        assert_eq!(attestation.node_id, "node_123");
        assert!(attestation.timestamp > 0);
        assert!(attestation.expiration > attestation.timestamp);
    }

    #[test]
    fn test_attestation_validation() {
        let security_config = SecurityConfig::default();
        let mut attestation = Attestation::new("node_123", &security_config).unwrap();

        assert!(attestation.is_valid());

        // Simulate expiration
        attestation.expiration = attestation.timestamp - 1000;
        assert!(!attestation.is_valid());
    }

    #[test]
    fn test_security_level_calculation() {
        let hardware_info = HardwareInfo {
            cpu_info: CpuInfo {
                vendor: "Intel".to_string(),
                model: "Core i7-9700K".to_string(),
                cores: 8,
                threads: 8,
                architecture: "x86_64".to_string(),
                flags: vec!["sse4_2".to_string(), "avx2".to_string()],
                trusted_execution: true,
            },
            memory_info: MemoryInfo {
                total_memory_bytes: 16 * 1024 * 1024 * 1024,
                available_memory_bytes: 8 * 1024 * 1024 * 1024,
                memory_speed_mhz: 3200,
                memory_type: "DDR4".to_string(),
                ecc_enabled: false,
            },
            storage_info: StorageInfo {
                total_storage_bytes: 512 * 1024 * 1024 * 1024,
                available_storage_bytes: 256 * 1024 * 1024 * 1024,
                storage_type: "NVMe SSD".to_string(),
                encryption_enabled: true,
            },
            network_info: NetworkInfo {
                mac_address: "00:11:22:33:44:55".to_string(),
                ip_addresses: vec!["192.168.1.100".to_string()],
                network_speed_mbps: 1000,
                trusted_network: true,
            },
            security_features: SecurityFeatures {
                trusted_execution_supported: true,
                secure_boot_enabled: true,
                tpm_available: true,
                virtualization_enabled: true,
                firewall_enabled: true,
            },
        };

        let software_info = SoftwareInfo {
            os_info: OsInfo {
                name: "Linux".to_string(),
                version: "5.15.0-76-generic".to_string(),
                architecture: "x86_64".to_string(),
                kernel_version: "5.15.0-76-generic".to_string(),
            },
            kernel_info: KernelInfo {
                version: "5.15.0-76-generic".to_string(),
                security_patches: vec!["CVE-2023-1234".to_string()],
                capabilities: vec!["seccomp".to_string(), "apparmor".to_string()],
            },
            runtime_info: RuntimeInfo {
                auria_version: "1.0.0".to_string(),
                rust_version: "1.70.0".to_string(),
                features: vec!["crypto".to_string(), "attestation".to_string()],
                build_info: "debug".to_string(),
            },
            security_patches: vec!["2023-001".to_string()],
        };

        let security_config = SecurityConfig::default();
        let security_state = SecurityState::evaluate(&hardware_info, &software_info, &security_config).unwrap();

        assert!(security_state.security_level >= SecurityLevel::High);
        assert!(!security_state.vulnerabilities.is_empty());
        assert!(security_state.compliance_status >= ComplianceStatus::Compliant);
    }
}