use recovery_core::binary_reader::BinaryReader;
use recovery_core::error::{RecoveryError, Result};
use recovery_core::types::Cluster;
use std::fmt;

#[derive(Debug, Clone)]
pub struct NtfsVbr {
    pub oem_id: String,
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub total_sectors: u64,
    pub mft_start_cluster: Cluster,
    pub mft_mirr_start_cluster: Cluster,
    pub clusters_per_mft_record: i8,
    pub clusters_per_index_block: i8,
    pub volume_serial_number: u64,
}

impl NtfsVbr {
    pub fn parse(sector_data: &[u8]) -> Result<Self> {
        if sector_data.len() < 512 {
            return Err(RecoveryError::BufferOutOfBounds {
                offset: 0,
                required: 512,
                available: sector_data.len(),
            });
        }

        let magic_510 = BinaryReader::peek_u16_le_at(sector_data, 510)?;
        if magic_510 != 0xAA55 {
            return Err(RecoveryError::InvalidSignature {
                expected: "0xAA55".into(),
                found: format!("{:#06X}", magic_510),
            });
        }

        let oem_id = BinaryReader::peek_bytes_at(sector_data, 3, 8)?;
        if oem_id != b"NTFS    " {
            return Err(RecoveryError::InvalidSignature {
                expected: "NTFS    ".into(),
                found: String::from_utf8_lossy(oem_id).to_string(),
            });
        }

        let mut reader = BinaryReader::new(sector_data);
        reader.skip(3)?; // Skip jump instruction
        let oem_str = reader.read_ascii_string(8)?;
        let bytes_per_sector = reader.read_u16_le()?;
        let sectors_per_cluster = reader.read_u8()?;
        reader.skip(7)?; // Reserved
        let _media_descriptor = reader.read_u8()?;
        reader.skip(18)?; // Unused BPB fields
        let total_sectors = reader.read_u64_le()?;
        let mft_start_cluster = reader.read_u64_le()?;
        let mft_mirr_start_cluster = reader.read_u64_le()?;
        let clusters_per_mft_record = reader.read_u8()? as i8;
        reader.skip(3)?;
        let clusters_per_index_block = reader.read_u8()? as i8;
        reader.skip(3)?;
        let volume_serial_number = reader.read_u64_le()?;

        Ok(Self {
            oem_id: oem_str,
            bytes_per_sector,
            sectors_per_cluster,
            total_sectors,
            mft_start_cluster,
            mft_mirr_start_cluster,
            clusters_per_mft_record,
            clusters_per_index_block,
            volume_serial_number,
        })
    }

    pub fn bytes_per_cluster(&self) -> u32 {
        self.bytes_per_sector as u32 * self.sectors_per_cluster as u32
    }

    pub fn mft_record_size(&self) -> u32 {
        if self.clusters_per_mft_record > 0 {
            self.clusters_per_mft_record as u32 * self.bytes_per_cluster()
        } else {
            // Negative value represents 2^|n| bytes (typically -10 = 1024 bytes)
            1u32 << (-self.clusters_per_mft_record as u32)
        }
    }

    pub fn index_record_size(&self) -> u32 {
        if self.clusters_per_index_block > 0 {
            self.clusters_per_index_block as u32 * self.bytes_per_cluster()
        } else {
            1u32 << (-self.clusters_per_index_block as u32)
        }
    }

    pub fn mft_start_byte_offset(&self) -> u64 {
        self.mft_start_cluster * self.bytes_per_cluster() as u64
    }
}

impl fmt::Display for NtfsVbr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "NTFS Volume Boot Record:")?;
        writeln!(f, "  OEM ID:               '{}'", self.oem_id)?;
        writeln!(f, "  Bytes per Sector:     {}", self.bytes_per_sector)?;
        writeln!(f, "  Sectors per Cluster:  {} ({} bytes/cluster)", self.sectors_per_cluster, self.bytes_per_cluster())?;
        writeln!(f, "  Total Sectors:        {} ({:.2} GB)", self.total_sectors, (self.total_sectors as f64 * self.bytes_per_sector as f64) / (1024.0 * 1024.0 * 1024.0))?;
        writeln!(f, "  $MFT Start Cluster:   LCN {} (Byte Offset: {:#X})", self.mft_start_cluster, self.mft_start_byte_offset())?;
        writeln!(f, "  $MFTMirr Cluster:     LCN {}", self.mft_mirr_start_cluster)?;
        writeln!(f, "  MFT Record Size:      {} bytes", self.mft_record_size())?;
        writeln!(f, "  Index Record Size:    {} bytes", self.index_record_size())?;
        writeln!(f, "  Volume Serial:        {:#018X}", self.volume_serial_number)?;
        Ok(())
    }
}
