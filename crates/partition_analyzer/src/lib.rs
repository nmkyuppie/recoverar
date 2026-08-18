pub mod mbr;
pub mod gpt;
pub mod heuristics;

pub use mbr::{MasterBootRecord, MbrPartitionEntry};
pub use gpt::{GuidPartitionTable, GptHeader, GptPartitionEntry};
pub use heuristics::{DiscoveredBootSector, FileSystemType, HeuristicPartitionScanner};

use disk_io::block_reader::BlockDevice;
use recovery_core::error::Result;

#[derive(Debug)]
pub enum PartitionScheme {
    Gpt {
        primary: Option<GuidPartitionTable>,
        backup: Option<GuidPartitionTable>,
    },
    Mbr(MasterBootRecord),
    RawOrUnknown,
}

pub struct PartitionAnalyzer;

impl PartitionAnalyzer {
    pub fn analyze(device: &mut dyn BlockDevice) -> Result<PartitionScheme> {
        let sector_size = device.sector_size() as usize;
        let mut lba0 = vec![0u8; sector_size];
        let mut lba1 = vec![0u8; sector_size];

        device.read_exact_at(0, &mut lba0)?;
        let mbr_res = MasterBootRecord::parse(&lba0);

        // Check if GPT is present
        if device.read_exact_at(sector_size as u64, &mut lba1).is_ok() {
            if let Ok(primary_hdr) = GptHeader::parse(&lba1) {
                // Read partition entry array (usually 128 entries * 128 bytes = 16384 bytes)
                let array_size = (primary_hdr.num_partition_entries * primary_hdr.size_of_partition_entry) as usize;
                let mut array_buf = vec![0u8; array_size];
                let array_offset = primary_hdr.partition_entry_lba * sector_size as u64;

                let primary = if device.read_exact_at(array_offset, &mut array_buf).is_ok() {
                    GuidPartitionTable::parse(&lba1, &array_buf, false).ok()
                } else {
                    None
                };

                // Check backup GPT at disk tail
                let total_size = device.total_size();
                let backup = if total_size > (sector_size as u64 * 34) {
                    let backup_hdr_offset = total_size - sector_size as u64;
                    let mut backup_hdr_buf = vec![0u8; sector_size];

                    if device.read_exact_at(backup_hdr_offset, &mut backup_hdr_buf).is_ok() {
                        if let Ok(b_hdr) = GptHeader::parse(&backup_hdr_buf) {
                            let b_array_size = (b_hdr.num_partition_entries * b_hdr.size_of_partition_entry) as usize;
                            let mut b_array_buf = vec![0u8; b_array_size];
                            let b_array_offset = b_hdr.partition_entry_lba * sector_size as u64;

                            if device.read_exact_at(b_array_offset, &mut b_array_buf).is_ok() {
                                GuidPartitionTable::parse(&backup_hdr_buf, &b_array_buf, true).ok()
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                return Ok(PartitionScheme::Gpt { primary, backup });
            }
        }

        if let Ok(mbr) = mbr_res {
            return Ok(PartitionScheme::Mbr(mbr));
        }

        Ok(PartitionScheme::RawOrUnknown)
    }

    /// Automatically find all partition offsets across MBR, Extended EBR chains, and GPT.
    pub fn detect_all_volumes(device: &mut dyn BlockDevice) -> Vec<DiscoveredBootSector> {
        let sector_size = device.sector_size() as usize;
        let mut volumes = Vec::new();

        // 1. Try Partition Table
        if let Ok(scheme) = Self::analyze(device) {
            match scheme {
                PartitionScheme::Gpt { primary, .. } => {
                    if let Some(gpt) = primary {
                        for p in gpt.partitions {
                            let offset = p.start_lba * sector_size as u64;
                            let mut buf = vec![0u8; sector_size];
                            if device.read_exact_at(offset, &mut buf).is_ok() {
                                if let Some(boot) = HeuristicPartitionScanner::inspect_sector(p.start_lba, &buf) {
                                    volumes.push(boot);
                                    continue;
                                }
                            }
                            volumes.push(DiscoveredBootSector {
                                fs_type: FileSystemType::Unknown(p.type_description().to_string()),
                                start_lba: p.start_lba,
                                bytes_per_sector: sector_size as u32,
                                sectors_per_cluster: 8,
                                total_sectors: p.sector_count(),
                                volume_label: if p.name.is_empty() { format!("GPT_Part_{}", p.index + 1) } else { p.name },
                            });
                        }
                    }
                }
                PartitionScheme::Mbr(mbr) => {
                    for p in mbr.partitions {
                        if !p.is_extended {
                            let offset = p.start_lba * sector_size as u64;
                            let mut buf = vec![0u8; sector_size];
                            if device.read_exact_at(offset, &mut buf).is_ok() {
                                if let Some(boot) = HeuristicPartitionScanner::inspect_sector(p.start_lba, &buf) {
                                    volumes.push(boot);
                                    continue;
                                }
                            }
                            volumes.push(DiscoveredBootSector {
                                fs_type: FileSystemType::Ntfs,
                                start_lba: p.start_lba,
                                bytes_per_sector: sector_size as u32,
                                sectors_per_cluster: 8,
                                total_sectors: p.sector_count,
                                volume_label: format!("Partition_{}_{}", p.slot + 1, p.type_name()),
                            });
                        } else {
                            // Parse EBR Extended Logical Partition Chain
                            let mut current_ebr_lba = p.start_lba;
                            let extended_base_lba = p.start_lba;
                            let mut visited = std::collections::HashSet::new();

                            while current_ebr_lba != 0 && visited.insert(current_ebr_lba) {
                                let mut ebr_buf = vec![0u8; sector_size];
                                let ebr_offset = current_ebr_lba * sector_size as u64;
                                if device.read_exact_at(ebr_offset, &mut ebr_buf).is_err() {
                                    break;
                                }

                                if let Ok(magic) = recovery_core::binary_reader::BinaryReader::peek_u16_le_at(&ebr_buf, 510) {
                                    if magic != 0xAA55 {
                                        break;
                                    }
                                }

                                // Entry 1: Logical partition
                                if let Ok(Some(log_entry)) = MbrPartitionEntry::parse(0, &ebr_buf[446..462]) {
                                    let log_start_lba = current_ebr_lba + log_entry.start_lba;
                                    let log_offset = log_start_lba * sector_size as u64;
                                    let mut boot_buf = vec![0u8; sector_size];
                                    if device.read_exact_at(log_offset, &mut boot_buf).is_ok() {
                                        if let Some(boot) = HeuristicPartitionScanner::inspect_sector(log_start_lba, &boot_buf) {
                                            volumes.push(boot);
                                        } else {
                                            volumes.push(DiscoveredBootSector {
                                                fs_type: FileSystemType::Ntfs,
                                                start_lba: log_start_lba,
                                                bytes_per_sector: sector_size as u32,
                                                sectors_per_cluster: 8,
                                                total_sectors: log_entry.sector_count,
                                                volume_label: format!("Logical_Part_LBA_{}", log_start_lba),
                                            });
                                        }
                                    }
                                }

                                // Entry 2: Next EBR
                                if let Ok(Some(next_ebr)) = MbrPartitionEntry::parse(1, &ebr_buf[462..478]) {
                                    if next_ebr.start_lba > 0 {
                                        current_ebr_lba = extended_base_lba + next_ebr.start_lba;
                                    } else {
                                        break;
                                    }
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                }
                PartitionScheme::RawOrUnknown => {}
            }
        }

        // Deduplicate volumes by start LBA
        let mut unique = Vec::new();
        for v in volumes {
            if !unique.iter().any(|u: &DiscoveredBootSector| u.start_lba == v.start_lba) {
                unique.push(v);
            }
        }

        unique
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crc32fast::Hasher;

    #[test]
    fn test_mbr_parsing() {
        let mut sector = vec![0u8; 512];
        sector[510] = 0x55;
        sector[511] = 0xAA;

        // Partition 1 at 446
        sector[446] = 0x80; // Bootable
        sector[450] = 0x07; // NTFS
        sector[454..458].copy_from_slice(&2048u32.to_le_bytes()); // Start LBA 2048
        sector[458..462].copy_from_slice(&204800u32.to_le_bytes()); // 204800 sectors

        let mbr = MasterBootRecord::parse(&sector).unwrap();
        assert_eq!(mbr.partitions.len(), 1);
        assert_eq!(mbr.partitions[0].is_bootable, true);
        assert_eq!(mbr.partitions[0].start_lba, 2048);
        assert_eq!(mbr.partitions[0].partition_type, 0x07);
    }

    #[test]
    fn test_gpt_header_crc_validation() {
        let mut hdr = vec![0u8; 512];
        hdr[0..8].copy_from_slice(b"EFI PART");
        hdr[8..12].copy_from_slice(&0x00010000u32.to_le_bytes()); // Rev 1.0
        hdr[12..16].copy_from_slice(&92u32.to_le_bytes()); // Header size 92
        hdr[24..32].copy_from_slice(&1u64.to_le_bytes()); // Current LBA 1
        hdr[32..40].copy_from_slice(&20000u64.to_le_bytes()); // Backup LBA
        hdr[40..48].copy_from_slice(&34u64.to_le_bytes()); // First usable
        hdr[48..56].copy_from_slice(&19966u64.to_le_bytes()); // Last usable
        hdr[72..80].copy_from_slice(&2u64.to_le_bytes()); // Partition array LBA 2
        hdr[80..84].copy_from_slice(&128u32.to_le_bytes()); // 128 entries
        hdr[84..88].copy_from_slice(&128u32.to_le_bytes()); // 128 bytes each

        // Calculate Header CRC
        let mut hasher = Hasher::new();
        hasher.update(&hdr[0..92]);
        let crc = hasher.finalize();
        hdr[16..20].copy_from_slice(&crc.to_le_bytes());

        let parsed = GptHeader::parse(&hdr).unwrap();
        assert_eq!(parsed.current_lba, 1);
        assert_eq!(parsed.num_partition_entries, 128);
    }
}
