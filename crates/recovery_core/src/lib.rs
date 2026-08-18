pub mod error;
pub mod types;
pub mod binary_reader;

pub use error::{RecoveryError, Result};
pub use types::{SectorSize, Lba, Cluster, ByteRange, Guid, filetime_to_datetime};
pub use binary_reader::BinaryReader;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_reader_primitives() {
        let buffer = [0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00];
        let mut reader = BinaryReader::new(&buffer);
        assert_eq!(reader.read_u8().unwrap(), 0x12);
        assert_eq!(reader.read_u16_le().unwrap(), 0x5634);
    }

    #[test]
    fn test_guid_parse() {
        let raw = [
            0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
            0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B
        ];
        let guid = Guid::from_bytes_le(&raw).unwrap();
        assert_eq!(guid.to_string(), "C12A7328-F81F-11D2-BA4B-00A0C93EC93B");
    }

    #[test]
    fn test_filetime_converter() {
        // 2021-01-01 00:00:00 UTC = FILETIME 132539328000000000
        let ft = 132539328000000000u64;
        let dt = filetime_to_datetime(ft).unwrap();
        assert_eq!(dt.to_rfc3339(), "2021-01-01T00:00:00+00:00");
    }
}
