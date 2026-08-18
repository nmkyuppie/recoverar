use crate::attribute::{
    AttributeData, AttributeType, FileNameAttribute, NtfsAttribute, StandardInformation,
};
use crate::usn::UsnFixup;
use recovery_core::binary_reader::BinaryReader;
use recovery_core::error::{RecoveryError, Result};
use std::fmt;

pub const MFT_RECORD_MAGIC_FILE: &[u8; 4] = b"FILE";
pub const MFT_RECORD_MAGIC_BAAD: &[u8; 4] = b"BAAD";

pub const MFT_RECORD_IN_USE: u16 = 0x0001;
pub const MFT_RECORD_IS_DIRECTORY: u16 = 0x0002;

#[derive(Debug, Clone)]
pub struct MftRecord {
    pub record_number: u64,
    pub sequence_number: u16,
    pub hard_link_count: u16,
    pub is_in_use: bool,
    pub is_directory: bool,
    pub base_record_ref: u64,
    pub attributes: Vec<NtfsAttribute>,
}

impl MftRecord {
    pub fn parse(
        record_bytes: &[u8],
        record_number: u64,
        bytes_per_sector: usize,
    ) -> Result<Self> {
        if record_bytes.len() < 48 {
            return Err(RecoveryError::BufferOutOfBounds {
                offset: 0,
                required: 48,
                available: record_bytes.len(),
            });
        }

        let magic = &record_bytes[0..4];
        if magic != MFT_RECORD_MAGIC_FILE {
            return Err(RecoveryError::InvalidSignature {
                expected: "FILE".into(),
                found: String::from_utf8_lossy(magic).to_string(),
            });
        }

        // Make mutable copy to apply USN fixups
        let mut fixed_buf = record_bytes.to_vec();
        UsnFixup::apply_fixup(&mut fixed_buf, bytes_per_sector)?;

        let mut reader = BinaryReader::new(&fixed_buf);
        reader.skip(16)?; // Skip magic, USA offset, USA count, LSN
        let sequence_number = reader.read_u16_le()?;
        let hard_link_count = reader.read_u16_le()?;
        let first_attr_offset = reader.read_u16_le()? as usize;
        let flags = reader.read_u16_le()?;
        let _used_bytes = reader.read_u32_le()?;
        let _alloc_bytes = reader.read_u32_le()?;
        let base_record_ref = reader.read_u64_le()?;

        let is_in_use = (flags & MFT_RECORD_IN_USE) != 0;
        let is_directory = (flags & MFT_RECORD_IS_DIRECTORY) != 0;

        // Parse attributes
        let mut attributes = Vec::new();
        let mut offset = first_attr_offset;

        while offset < fixed_buf.len() {
            match NtfsAttribute::parse(&fixed_buf, offset)? {
                Some(attr) => {
                    let len = attr.record_length as usize;
                    if len == 0 {
                        break;
                    }
                    offset += len;
                    attributes.push(attr);
                }
                None => break,
            }
        }

        Ok(Self {
            record_number,
            sequence_number,
            hard_link_count,
            is_in_use,
            is_directory,
            base_record_ref,
            attributes,
        })
    }

    /// Extract standard information attribute if present.
    pub fn standard_info(&self) -> Option<StandardInformation> {
        for attr in &self.attributes {
            if attr.attr_type == AttributeType::StandardInformation {
                if let AttributeData::Resident(ref bytes) = attr.data {
                    return StandardInformation::parse(bytes).ok();
                }
            }
        }
        None
    }

    /// Extract primary file name attribute (prefers Win32/POSIX namespace over DOS).
    pub fn file_name(&self) -> Option<FileNameAttribute> {
        let mut best_fn: Option<FileNameAttribute> = None;
        for attr in &self.attributes {
            if attr.attr_type == AttributeType::FileName {
                if let AttributeData::Resident(ref bytes) = attr.data {
                    if let Ok(fn_attr) = FileNameAttribute::parse(bytes) {
                        if fn_attr.namespace == 1 || fn_attr.namespace == 3 {
                            // Win32 or Win32 & DOS
                            return Some(fn_attr);
                        } else if best_fn.is_none() {
                            best_fn = Some(fn_attr);
                        }
                    }
                }
            }
        }
        best_fn
    }

    /// Extract default unnamed $DATA attribute.
    pub fn data_attribute(&self) -> Option<&NtfsAttribute> {
        self.attributes.iter().find(|a| a.attr_type == AttributeType::Data && a.name.is_empty())
    }
}

impl fmt::Display for MftRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fn_attr = self.file_name();
        let name = fn_attr.as_ref().map(|f| f.name.as_str()).unwrap_or("<unknown>");
        let size = fn_attr.as_ref().map(|f| f.real_size).unwrap_or(0);

        write!(
            f,
            "MFT #{}: '{}' [{}] - Size: {}B (Attributes: {})",
            self.record_number,
            name,
            if self.is_directory { "DIR" } else { "FILE" },
            size,
            self.attributes.len()
        )
    }
}
