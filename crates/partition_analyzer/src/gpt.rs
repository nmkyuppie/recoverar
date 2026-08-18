use crc32fast::Hasher;
use recovery_core::binary_reader::BinaryReader;
use recovery_core::error::{RecoveryError, Result};
use recovery_core::types::{Guid, Lba};
use std::fmt;

pub const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";

// Well-known Partition Type GUIDs
pub const GUID_EFI_SYSTEM: &str = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
pub const GUID_MICROSOFT_BASIC_DATA: &str = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7";
pub const GUID_MICROSOFT_RESERVED: &str = "E3C9E316-0B5C-4DB8-817D-F92DF00215AE";
pub const GUID_MICROSOFT_RECOVERY: &str = "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC";
pub const GUID_LINUX_FILESYSTEM: &str = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
pub const GUID_LINUX_SWAP: &str = "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F";
pub const GUID_LINUX_LVM: &str = "E6D6D379-F507-44C2-A23C-238F2A3DF928";
pub const GUID_APFS: &str = "7C3457EF-0000-11AA-AA11-00306543ECAC";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptPartitionEntry {
    pub index: usize,
    pub type_guid: Guid,
    pub unique_guid: Guid,
    pub start_lba: Lba,
    pub end_lba: Lba,
    pub attributes: u64,
    pub name: String,
}

impl GptPartitionEntry {
    pub fn parse(index: usize, data: &[u8]) -> Result<Option<Self>> {
        if data.len() < 128 {
            return Err(RecoveryError::BufferOutOfBounds {
                offset: 0,
                required: 128,
                available: data.len(),
            });
        }

        let mut reader = BinaryReader::new(data);
        let type_guid = reader.read_guid_le()?;
        if type_guid.is_zero() {
            return Ok(None);
        }

        let unique_guid = reader.read_guid_le()?;
        let start_lba = reader.read_u64_le()?;
        let end_lba = reader.read_u64_le()?;
        let attributes = reader.read_u64_le()?;
        let name = reader.read_utf16_le_string(36)?.trim_end_matches('\0').to_string();

        Ok(Some(Self {
            index,
            type_guid,
            unique_guid,
            start_lba,
            end_lba,
            attributes,
            name,
        }))
    }

    pub fn sector_count(&self) -> u64 {
        if self.end_lba >= self.start_lba {
            self.end_lba - self.start_lba + 1
        } else {
            0
        }
    }

    pub fn type_description(&self) -> &'static str {
        let guid_str = self.type_guid.to_string();
        match guid_str.as_str() {
            GUID_EFI_SYSTEM => "EFI System Partition",
            GUID_MICROSOFT_BASIC_DATA => "Microsoft Basic Data (NTFS/FAT/exFAT)",
            GUID_MICROSOFT_RESERVED => "Microsoft Reserved (MSR)",
            GUID_MICROSOFT_RECOVERY => "Windows Recovery Environment",
            GUID_LINUX_FILESYSTEM => "Linux Filesystem Data",
            GUID_LINUX_SWAP => "Linux Swap",
            GUID_LINUX_LVM => "Linux LVM",
            GUID_APFS => "Apple APFS",
            _ => "Unknown / Other Partition Type",
        }
    }
}

#[derive(Debug, Clone)]
pub struct GptHeader {
    pub revision: u32,
    pub header_size: u32,
    pub header_crc32: u32,
    pub current_lba: Lba,
    pub backup_lba: Lba,
    pub first_usable_lba: Lba,
    pub last_usable_lba: Lba,
    pub disk_guid: Guid,
    pub partition_entry_lba: Lba,
    pub num_partition_entries: u32,
    pub size_of_partition_entry: u32,
    pub partition_array_crc32: u32,
}

impl GptHeader {
    pub fn parse(header_bytes: &[u8]) -> Result<Self> {
        if header_bytes.len() < 92 {
            return Err(RecoveryError::BufferOutOfBounds {
                offset: 0,
                required: 92,
                available: header_bytes.len(),
            });
        }

        if &header_bytes[0..8] != GPT_SIGNATURE {
            return Err(RecoveryError::InvalidSignature {
                expected: "EFI PART".into(),
                found: String::from_utf8_lossy(&header_bytes[0..8]).to_string(),
            });
        }

        let mut reader = BinaryReader::new(header_bytes);
        reader.skip(8)?; // Skip signature
        let revision = reader.read_u32_le()?;
        let header_size = reader.read_u32_le()?;
        let header_crc32 = reader.read_u32_le()?;
        let _reserved = reader.read_u32_le()?;
        let current_lba = reader.read_u64_le()?;
        let backup_lba = reader.read_u64_le()?;
        let first_usable_lba = reader.read_u64_le()?;
        let last_usable_lba = reader.read_u64_le()?;
        let disk_guid = reader.read_guid_le()?;
        let partition_entry_lba = reader.read_u64_le()?;
        let num_partition_entries = reader.read_u32_le()?;
        let size_of_partition_entry = reader.read_u32_le()?;
        let partition_array_crc32 = reader.read_u32_le()?;

        // Validate Header CRC32
        if (header_size as usize) <= header_bytes.len() {
            let mut crc_buf = header_bytes[0..header_size as usize].to_vec();
            crc_buf[16..20].copy_from_slice(&[0, 0, 0, 0]); // Zero out CRC field for verification
            let mut hasher = Hasher::new();
            hasher.update(&crc_buf);
            let computed = hasher.finalize();

            if computed != header_crc32 {
                return Err(RecoveryError::CrcMismatch {
                    expected: header_crc32,
                    computed,
                });
            }
        }

        Ok(Self {
            revision,
            header_size,
            header_crc32,
            current_lba,
            backup_lba,
            first_usable_lba,
            last_usable_lba,
            disk_guid,
            partition_entry_lba,
            num_partition_entries,
            size_of_partition_entry,
            partition_array_crc32,
        })
    }
}

#[derive(Debug, Clone)]
pub struct GuidPartitionTable {
    pub is_backup: bool,
    pub header: GptHeader,
    pub partitions: Vec<GptPartitionEntry>,
}

impl GuidPartitionTable {
    pub fn parse(header_bytes: &[u8], array_bytes: &[u8], is_backup: bool) -> Result<Self> {
        let header = GptHeader::parse(header_bytes)?;

        // Verify Partition Array CRC32
        let total_array_bytes = (header.num_partition_entries as usize) * (header.size_of_partition_entry as usize);
        if array_bytes.len() < total_array_bytes {
            return Err(RecoveryError::BufferOutOfBounds {
                offset: 0,
                required: total_array_bytes,
                available: array_bytes.len(),
            });
        }

        let mut hasher = Hasher::new();
        hasher.update(&array_bytes[..total_array_bytes]);
        let computed_array_crc = hasher.finalize();

        if computed_array_crc != header.partition_array_crc32 {
            return Err(RecoveryError::CrcMismatch {
                expected: header.partition_array_crc32,
                computed: computed_array_crc,
            });
        }

        let mut partitions = Vec::new();
        let entry_size = header.size_of_partition_entry as usize;

        for i in 0..header.num_partition_entries as usize {
            let offset = i * entry_size;
            let entry_slice = &array_bytes[offset..offset + entry_size];
            if let Some(entry) = GptPartitionEntry::parse(i, entry_slice)? {
                partitions.push(entry);
            }
        }

        Ok(Self {
            is_backup,
            header,
            partitions,
        })
    }
}

impl fmt::Display for GuidPartitionTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{} GPT (Disk GUID: {}):",
            if self.is_backup { "Backup" } else { "Primary" },
            self.header.disk_guid
        )?;
        writeln!(
            f,
            "  Header LBA: {} | Backup LBA: {} | Usable Range: {}..={}",
            self.header.current_lba,
            self.header.backup_lba,
            self.header.first_usable_lba,
            self.header.last_usable_lba
        )?;
        writeln!(f, "  Partitions ({} total active):", self.partitions.len())?;
        for p in &self.partitions {
            let size_gb = (p.sector_count() * 512) as f64 / (1024.0 * 1024.0 * 1024.0);
            writeln!(
                f,
                "    #{}: [{}] LBA {}..={} ({} sectors, {:.2} GB) - Type: {}",
                p.index + 1,
                if p.name.is_empty() { "Unnamed" } else { &p.name },
                p.start_lba,
                p.end_lba,
                p.sector_count(),
                size_gb,
                p.type_description()
            )?;
        }
        Ok(())
    }
}
