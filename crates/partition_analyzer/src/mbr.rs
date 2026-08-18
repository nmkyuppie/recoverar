use recovery_core::binary_reader::BinaryReader;
use recovery_core::error::{RecoveryError, Result};
use recovery_core::types::Lba;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MbrPartitionEntry {
    pub slot: usize,
    pub is_bootable: bool,
    pub partition_type: u8,
    pub start_lba: Lba,
    pub sector_count: u64,
    pub is_extended: bool,
}

impl MbrPartitionEntry {
    pub fn parse(slot: usize, data: &[u8]) -> Result<Option<Self>> {
        if data.len() < 16 {
            return Err(RecoveryError::BufferOutOfBounds {
                offset: 0,
                required: 16,
                available: data.len(),
            });
        }

        let mut reader = BinaryReader::new(data);
        let boot_indicator = reader.read_u8()?;
        let _chs_start = reader.read_bytes(3)?;
        let partition_type = reader.read_u8()?;
        let _chs_end = reader.read_bytes(3)?;
        let start_lba = reader.read_u32_le()? as u64;
        let sector_count = reader.read_u32_le()? as u64;

        if partition_type == 0x00 && sector_count == 0 {
            return Ok(None);
        }

        let is_bootable = boot_indicator == 0x80;
        let is_extended = matches!(partition_type, 0x05 | 0x0F);

        Ok(Some(Self {
            slot,
            is_bootable,
            partition_type,
            start_lba,
            sector_count,
            is_extended,
        }))
    }

    pub fn type_name(&self) -> &'static str {
        match self.partition_type {
            0x00 => "Empty",
            0x01 => "FAT12",
            0x04 => "FAT16 (<32MB)",
            0x05 => "Extended (CHS)",
            0x06 => "FAT16 (>32MB)",
            0x07 => "NTFS / exFAT",
            0x0B => "FAT32 (CHS)",
            0x0C => "FAT32 (LBA)",
            0x0E => "FAT16 (LBA)",
            0x0F => "Extended (LBA)",
            0x27 => "Windows Recovery (WinRE)",
            0x82 => "Linux Swap",
            0x83 => "Linux Native (ext2/3/4)",
            0x8E => "Linux LVM",
            0xEE => "GPT Protective MBR",
            0xEF => "EFI System Partition",
            _ => "Unknown / Custom",
        }
    }
}

#[derive(Debug, Clone)]
pub struct MasterBootRecord {
    pub is_protective_gpt: bool,
    pub disk_signature: u32,
    pub partitions: Vec<MbrPartitionEntry>,
}

impl MasterBootRecord {
    pub fn parse(sector_data: &[u8]) -> Result<Self> {
        if sector_data.len() < 512 {
            return Err(RecoveryError::BufferOutOfBounds {
                offset: 0,
                required: 512,
                available: sector_data.len(),
            });
        }

        let magic = BinaryReader::peek_u16_le_at(sector_data, 510)?;
        if magic != 0xAA55 {
            return Err(RecoveryError::InvalidSignature {
                expected: "0xAA55".into(),
                found: format!("{:#06X}", magic),
            });
        }

        let disk_signature = BinaryReader::peek_u32_le_at(sector_data, 440)?;
        let mut partitions = Vec::new();
        let mut is_protective_gpt = false;

        for slot in 0..4 {
            let offset = 446 + (slot * 16);
            let entry_bytes = &sector_data[offset..offset + 16];
            if let Some(entry) = MbrPartitionEntry::parse(slot, entry_bytes)? {
                if entry.partition_type == 0xEE {
                    is_protective_gpt = true;
                }
                partitions.push(entry);
            }
        }

        Ok(Self {
            is_protective_gpt,
            disk_signature,
            partitions,
        })
    }
}

impl fmt::Display for MasterBootRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Master Boot Record (Signature: {:#010X}):", self.disk_signature)?;
        if self.is_protective_gpt {
            writeln!(f, "  [!] Protective MBR detected (Disk uses GPT partition table)")?;
        }
        for p in &self.partitions {
            writeln!(
                f,
                "  Slot {}: Start LBA: {} | Sectors: {} ({:.2} GB) | Type: {:#04X} ({}) | Boot: {}",
                p.slot,
                p.start_lba,
                p.sector_count,
                (p.sector_count * 512) as f64 / (1024.0 * 1024.0 * 1024.0),
                p.partition_type,
                p.type_name(),
                if p.is_bootable { "Yes" } else { "No" }
            )?;
        }
        Ok(())
    }
}
