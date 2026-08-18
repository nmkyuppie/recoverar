use disk_io::block_reader::BlockDevice;
use recovery_core::binary_reader::BinaryReader;
use recovery_core::error::Result;
use recovery_core::types::Lba;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileSystemType {
    Ntfs,
    Fat32,
    ExFat,
    Ext4,
    Unknown(String),
}

#[derive(Debug, Clone)]
pub struct DiscoveredBootSector {
    pub fs_type: FileSystemType,
    pub start_lba: Lba,
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub total_sectors: u64,
    pub volume_label: String,
}

impl fmt::Display for DiscoveredBootSector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fs_str = match &self.fs_type {
            FileSystemType::Ntfs => "NTFS",
            FileSystemType::Fat32 => "FAT32",
            FileSystemType::ExFat => "exFAT",
            FileSystemType::Ext4 => "ext4",
            FileSystemType::Unknown(s) => s.as_str(),
        };
        let size_gb = (self.total_sectors * self.bytes_per_sector as u64) as f64 / (1024.0 * 1024.0 * 1024.0);
        write!(
            f,
            "[{}] Start LBA: {} | Sector Size: {}B | Cluster Size: {}KB | Total: {} sectors ({:.2} GB) | Label: '{}'",
            fs_str,
            self.start_lba,
            self.bytes_per_sector,
            (self.bytes_per_sector * self.sectors_per_cluster) / 1024,
            self.total_sectors,
            size_gb,
            self.volume_label
        )
    }
}

pub struct HeuristicPartitionScanner {
    step_sectors: u64,
}

impl Default for HeuristicPartitionScanner {
    fn default() -> Self {
        Self { step_sectors: 1 }
    }
}

impl HeuristicPartitionScanner {
    pub fn new(step_sectors: u64) -> Self {
        Self {
            step_sectors: step_sectors.max(1),
        }
    }

    /// Scan a block device for orphaned VBR / PBR boot sectors.
    pub fn scan_device<F>(
        &self,
        device: &mut dyn BlockDevice,
        start_lba: Lba,
        max_sectors_to_scan: u64,
        mut progress_cb: F,
    ) -> Result<Vec<DiscoveredBootSector>>
    where
        F: FnMut(Lba, usize),
    {
        let sector_size = device.sector_size() as usize;
        let total_device_sectors = device.total_size() / sector_size as u64;
        let end_lba = (start_lba + max_sectors_to_scan).min(total_device_sectors);

        let mut found = Vec::new();
        let mut buffer = vec![0u8; sector_size];

        let mut current_lba = start_lba;
        while current_lba < end_lba {
            let offset = current_lba * sector_size as u64;
            if device.read_exact_at(offset, &mut buffer).is_ok() {
                if let Some(boot) = Self::inspect_sector(current_lba, &buffer) {
                    found.push(boot);
                }
            }

            if current_lba % 2048 == 0 {
                progress_cb(current_lba, found.len());
            }

            current_lba += self.step_sectors;
        }

        Ok(found)
    }

    pub fn inspect_sector(lba: Lba, sector: &[u8]) -> Option<DiscoveredBootSector> {
        if sector.len() < 512 {
            return None;
        }

        let magic_510 = BinaryReader::peek_u16_le_at(sector, 510).ok()?;
        if magic_510 != 0xAA55 {
            // Check for ext4 superblock (offset 1024 / signature at 0x38 = 0xEF53)
            if sector.len() >= 0x40 && BinaryReader::peek_u16_le_at(sector, 0x38).ok()? == 0xEF53 {
                let block_size_shift = BinaryReader::peek_u32_le_at(sector, 0x18).unwrap_or(2);
                let block_size = 1024u32 << block_size_shift;
                let blocks_count = BinaryReader::peek_u32_le_at(sector, 0x04).unwrap_or(0) as u64;
                let volume_name = BinaryReader::peek_bytes_at(sector, 0x78, 16)
                    .map(|b| String::from_utf8_lossy(b).trim_matches('\0').to_string())
                    .unwrap_or_default();

                return Some(DiscoveredBootSector {
                    fs_type: FileSystemType::Ext4,
                    start_lba: lba.saturating_sub(2), // superblock is usually at 1024 bytes (LBA 2)
                    bytes_per_sector: 512,
                    sectors_per_cluster: block_size / 512,
                    total_sectors: (blocks_count * block_size as u64) / 512,
                    volume_label: volume_name,
                });
            }
            return None;
        }

        // Check NTFS: OEM ID "NTFS    " at offset 3
        if &sector[3..11] == b"NTFS    " {
            let bytes_per_sec = BinaryReader::peek_u16_le_at(sector, 11).unwrap_or(512) as u32;
            let sec_per_cluster = sector[13] as u32;
            let total_sectors = BinaryReader::peek_u64_le_at(sector, 40).unwrap_or(0);

            return Some(DiscoveredBootSector {
                fs_type: FileSystemType::Ntfs,
                start_lba: lba,
                bytes_per_sector: if bytes_per_sec == 0 { 512 } else { bytes_per_sec },
                sectors_per_cluster: if sec_per_cluster == 0 { 8 } else { sec_per_cluster },
                total_sectors,
                volume_label: "NTFS Volume".to_string(),
            });
        }

        // Check FAT32: "FAT32   " at offset 82
        if sector.len() >= 90 && &sector[82..90] == b"FAT32   " {
            let bytes_per_sec = BinaryReader::peek_u16_le_at(sector, 11).unwrap_or(512) as u32;
            let sec_per_cluster = sector[13] as u32;
            let total_sectors_32 = BinaryReader::peek_u32_le_at(sector, 32).unwrap_or(0) as u64;
            let label_bytes = &sector[71..82];
            let label = String::from_utf8_lossy(label_bytes).trim().to_string();

            return Some(DiscoveredBootSector {
                fs_type: FileSystemType::Fat32,
                start_lba: lba,
                bytes_per_sector: if bytes_per_sec == 0 { 512 } else { bytes_per_sec },
                sectors_per_cluster: if sec_per_cluster == 0 { 8 } else { sec_per_cluster },
                total_sectors: total_sectors_32,
                volume_label: if label.is_empty() { "NO NAME".into() } else { label },
            });
        }

        // Check exFAT: "EXFAT   " at offset 3
        if &sector[3..11] == b"EXFAT   " {
            let bytes_per_sec_shift = sector[108];
            let sec_per_cluster_shift = sector[109];
            let bytes_per_sec = 1u32 << bytes_per_sec_shift;
            let sec_per_cluster = 1u32 << sec_per_cluster_shift;
            let total_sectors = BinaryReader::peek_u64_le_at(sector, 72).unwrap_or(0);

            return Some(DiscoveredBootSector {
                fs_type: FileSystemType::ExFat,
                start_lba: lba,
                bytes_per_sector: bytes_per_sec,
                sectors_per_cluster: sec_per_cluster,
                total_sectors,
                volume_label: "exFAT Volume".to_string(),
            });
        }

        None
    }
}
