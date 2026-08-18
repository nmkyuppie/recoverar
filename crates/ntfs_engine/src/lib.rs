pub mod vbr;
pub mod usn;
pub mod attribute;
pub mod mft;
pub mod tree;

pub use vbr::NtfsVbr;
pub use usn::UsnFixup;
pub use attribute::{AttributeData, AttributeType, DataRun, FileNameAttribute, NtfsAttribute, StandardInformation};
pub use mft::{MftRecord, MFT_RECORD_IS_DIRECTORY, MFT_RECORD_IN_USE};
pub use tree::{NtfsNode, NtfsVolumeTree};

use disk_io::block_reader::BlockDevice;
use recovery_core::error::{RecoveryError, Result};

pub struct NtfsEngine<'a> {
    device: &'a mut dyn BlockDevice,
    partition_start_byte_offset: u64,
    vbr: NtfsVbr,
}

impl<'a> NtfsEngine<'a> {
    pub fn open(device: &'a mut dyn BlockDevice, mut partition_start_byte_offset: u64) -> Result<Self> {
        let mut vbr_buf = vec![0u8; 512];
        
        // 1. Try exact offset
        let mut found_offset = None;
        if device.read_exact_at(partition_start_byte_offset, &mut vbr_buf).is_ok() {
            if NtfsVbr::parse(&vbr_buf).is_ok() {
                found_offset = Some(partition_start_byte_offset);
            }
        }

        // 2. Read 1MB chunk into RAM and search all sector boundaries in RAM in 0.01s
        if found_offset.is_none() {
            let probe_size = 1024 * 1024; // 1 MB (2048 sectors)
            let mut probe_buf = vec![0u8; probe_size];
            if device.read_exact_at(partition_start_byte_offset, &mut probe_buf).is_ok() {
                for sec in 0..2048 {
                    let sec_off = sec * 512;
                    if sec_off + 512 <= probe_buf.len() {
                        let sec_slice = &probe_buf[sec_off..sec_off + 512];
                        if NtfsVbr::parse(sec_slice).is_ok() {
                            found_offset = Some(partition_start_byte_offset + sec_off as u64);
                            break;
                        }
                    }
                }
            }
        }

        let final_offset = found_offset.ok_or_else(|| {
            RecoveryError::NtfsError(format!("No valid NTFS VBR boot sector found near offset {:#X}", partition_start_byte_offset))
        })?;

        device.read_exact_at(final_offset, &mut vbr_buf)?;
        let vbr = NtfsVbr::parse(&vbr_buf)?;

        Ok(Self {
            device,
            partition_start_byte_offset: final_offset,
            vbr,
        })
    }

    pub fn vbr(&self) -> &NtfsVbr {
        &self.vbr
    }

    /// Read a specific MFT record by its record index.
    pub fn read_mft_record(&mut self, record_number: u64) -> Result<MftRecord> {
        let record_size = self.vbr.mft_record_size() as usize;
        let mut record_buf = vec![0u8; record_size];

        let mft_start = self.partition_start_byte_offset + self.vbr.mft_start_byte_offset();
        let record_offset = mft_start + (record_number * record_size as u64);

        self.device.read_exact_at(record_offset, &mut record_buf)?;
        MftRecord::parse(&record_buf, record_number, self.vbr.bytes_per_sector as usize)
    }

    /// Parse MFT records up to max_records and construct directory tree.
    pub fn scan_volume_tree<F>(&mut self, max_records: u64, mut progress_cb: F) -> Result<NtfsVolumeTree>
    where
        F: FnMut(u64, usize),
    {
        let mut tree = NtfsVolumeTree::new(self.vbr.clone(), self.partition_start_byte_offset);
        let record_size = self.vbr.mft_record_size() as usize;
        let mut record_buf = vec![0u8; record_size];

        let mft_start = self.partition_start_byte_offset + self.vbr.mft_start_byte_offset();
        let mut consecutive_empty = 0;

        for rec_num in 0..max_records {
            let offset = mft_start + (rec_num * record_size as u64);
            if self.device.read_exact_at(offset, &mut record_buf).is_err() {
                break;
            }

            if &record_buf[0..4] == b"FILE" {
                if let Ok(rec) = MftRecord::parse(&record_buf, rec_num, self.vbr.bytes_per_sector as usize) {
                    tree.add_record(rec);
                    consecutive_empty = 0;
                }
            } else if record_buf.iter().all(|&b| b == 0) {
                consecutive_empty += 1;
                // Only stop if we have passed at least 5000 records and hit 2000 empty records
                if consecutive_empty > 2000 && rec_num > 5000 {
                    break;
                }
            }

            if rec_num % 500 == 0 {
                progress_cb(rec_num, tree.nodes.len());
            }
        }

        tree.build_hierarchy();
        Ok(tree)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vbr_parsing() {
        let mut vbr_data = vec![0u8; 512];
        vbr_data[510] = 0x55;
        vbr_data[511] = 0xAA;
        vbr_data[3..11].copy_from_slice(b"NTFS    ");
        vbr_data[11..13].copy_from_slice(&512u16.to_le_bytes()); // 512 bytes/sector
        vbr_data[13] = 8; // 8 sectors/cluster (4096 bytes)
        vbr_data[40..48].copy_from_slice(&2097152u64.to_le_bytes()); // Total sectors
        vbr_data[48..56].copy_from_slice(&786432u64.to_le_bytes()); // MFT start cluster LCN 786432
        vbr_data[56..64].copy_from_slice(&2u64.to_le_bytes()); // MFTMirr
        vbr_data[64] = 0xF6; // -10 (1024 bytes per MFT record)

        let vbr = NtfsVbr::parse(&vbr_data).unwrap();
        assert_eq!(vbr.bytes_per_sector, 512);
        assert_eq!(vbr.sectors_per_cluster, 8);
        assert_eq!(vbr.bytes_per_cluster(), 4096);
        assert_eq!(vbr.mft_record_size(), 1024);
        assert_eq!(vbr.mft_start_cluster, 786432);
    }

    #[test]
    fn test_usn_fixup_apply() {
        let mut record = vec![0u8; 1024];
        record[0..4].copy_from_slice(b"FILE");
        record[4..6].copy_from_slice(&48u16.to_le_bytes()); // USA offset 48
        record[6..8].copy_from_slice(&3u16.to_le_bytes());  // USA count 3 (USN + 2 sectors)

        // USA at offset 48: USN = 0x4242, Sector 1 orig = 0x1111, Sector 2 orig = 0x2222
        record[48..50].copy_from_slice(&0x4242u16.to_le_bytes());
        record[50..52].copy_from_slice(&0x1111u16.to_le_bytes());
        record[52..54].copy_from_slice(&0x2222u16.to_le_bytes());

        // End of sector 1 (offset 510) and sector 2 (offset 1022) must match USN 0x4242
        record[510..512].copy_from_slice(&0x4242u16.to_le_bytes());
        record[1022..1024].copy_from_slice(&0x4242u16.to_le_bytes());

        UsnFixup::apply_fixup(&mut record, 512).unwrap();

        // Verify restored original values
        assert_eq!(&record[510..512], &0x1111u16.to_le_bytes());
        assert_eq!(&record[1022..1024], &0x2222u16.to_le_bytes());
    }

    #[test]
    fn test_data_runlist_parsing() {
        // Runlist bytes:
        // [0x21, 0x18, 0x34, 0x12] -> Len 0x18 clusters (24), offset +0x1234 (4660)
        // [0x21, 0x10, 0x00, 0x01] -> Len 0x10 clusters (16), offset +0x0100 (256) -> LCN = 4660 + 256 = 4916
        // [0x00] -> End
        let run_bytes = [0x21, 0x18, 0x34, 0x12, 0x21, 0x10, 0x00, 0x01, 0x00];
        let runs = DataRun::parse_runlist(&run_bytes).unwrap();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].length_clusters, 24);
        assert_eq!(runs[0].lcn, Some(4660));
        assert_eq!(runs[1].length_clusters, 16);
        assert_eq!(runs[1].lcn, Some(4916));
    }
}
