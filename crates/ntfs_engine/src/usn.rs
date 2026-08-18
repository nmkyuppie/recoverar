use recovery_core::binary_reader::BinaryReader;
use recovery_core::error::{RecoveryError, Result};

pub struct UsnFixup;

impl UsnFixup {
    /// Applies Update Sequence Array (USA) fixups in-place to an MFT record buffer.
    pub fn apply_fixup(record_buffer: &mut [u8], bytes_per_sector: usize) -> Result<()> {
        if record_buffer.len() < 48 {
            return Err(RecoveryError::BufferOutOfBounds {
                offset: 0,
                required: 48,
                available: record_buffer.len(),
            });
        }

        let usa_offset = BinaryReader::peek_u16_le_at(record_buffer, 4)? as usize;
        let usa_count = BinaryReader::peek_u16_le_at(record_buffer, 6)? as usize;

        if usa_count < 2 {
            // Nothing to fixup
            return Ok(());
        }

        let usa_bytes_needed = usa_count * 2;
        if usa_offset + usa_bytes_needed > record_buffer.len() {
            return Err(RecoveryError::BufferOutOfBounds {
                offset: usa_offset,
                required: usa_bytes_needed,
                available: record_buffer.len().saturating_sub(usa_offset),
            });
        }

        // Expected USN (first 2 bytes of USA)
        let expected_usn = BinaryReader::peek_u16_le_at(record_buffer, usa_offset)?;
        let num_sectors = usa_count - 1;

        for i in 0..num_sectors {
            let sector_end_offset = (i + 1) * bytes_per_sector;
            if sector_end_offset > record_buffer.len() {
                break;
            }

            let marker_offset = sector_end_offset - 2;
            let actual_marker = BinaryReader::peek_u16_le_at(record_buffer, marker_offset)?;

            if actual_marker != expected_usn {
                return Err(RecoveryError::FixupFailed {
                    sector_index: i,
                    expected: expected_usn,
                    actual: actual_marker,
                });
            }

            // Restore original 2 bytes from USA[i + 1]
            let original_val_offset = usa_offset + ((i + 1) * 2);
            let orig_val_bytes = [
                record_buffer[original_val_offset],
                record_buffer[original_val_offset + 1],
            ];

            record_buffer[marker_offset] = orig_val_bytes[0];
            record_buffer[marker_offset + 1] = orig_val_bytes[1];
        }

        Ok(())
    }
}
