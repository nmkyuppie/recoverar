use chrono::{DateTime, Utc};
use recovery_core::binary_reader::BinaryReader;
use recovery_core::error::{RecoveryError, Result};
use recovery_core::types::{filetime_to_datetime, Cluster};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeType {
    StandardInformation,
    AttributeList,
    FileName,
    ObjectId,
    SecurityDescriptor,
    VolumeName,
    VolumeInformation,
    Data,
    IndexRoot,
    IndexAllocation,
    Bitmap,
    ReparsePoint,
    EaInformation,
    Ea,
    LoggedUtilityStream,
    EndMarker,
    Unknown(u32),
}

impl AttributeType {
    pub fn from_u32(val: u32) -> Self {
        match val {
            0x10 => AttributeType::StandardInformation,
            0x20 => AttributeType::AttributeList,
            0x30 => AttributeType::FileName,
            0x40 => AttributeType::ObjectId,
            0x50 => AttributeType::SecurityDescriptor,
            0x60 => AttributeType::VolumeName,
            0x70 => AttributeType::VolumeInformation,
            0x80 => AttributeType::Data,
            0x90 => AttributeType::IndexRoot,
            0xA0 => AttributeType::IndexAllocation,
            0xB0 => AttributeType::Bitmap,
            0xC0 => AttributeType::ReparsePoint,
            0xD0 => AttributeType::EaInformation,
            0xE0 => AttributeType::Ea,
            0x100 => AttributeType::LoggedUtilityStream,
            0xFFFFFFFF => AttributeType::EndMarker,
            other => AttributeType::Unknown(other),
        }
    }
}

/// Represents a contiguous cluster allocation run on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataRun {
    pub length_clusters: u64,
    /// Absolute starting cluster on disk (LCN). None indicates sparse run.
    pub lcn: Option<Cluster>,
}

impl DataRun {
    /// Parse NTFS mapping pairs runlist from binary slice.
    pub fn parse_runlist(mut data: &[u8]) -> Result<Vec<DataRun>> {
        let mut runs = Vec::new();
        let mut prev_lcn: i64 = 0;

        while !data.is_empty() {
            let header = data[0];
            if header == 0x00 {
                // End of runlist
                break;
            }

            let len_bytes = (header & 0x0F) as usize;
            let offset_bytes = ((header >> 4) & 0x0F) as usize;

            data = &data[1..];
            if data.len() < len_bytes + offset_bytes {
                return Err(RecoveryError::NtfsError(
                    "Malformed data run: unexpected end of runlist buffer".into(),
                ));
            }

            // Parse length (unsigned)
            let mut length_clusters: u64 = 0;
            for i in 0..len_bytes {
                length_clusters |= (data[i] as u64) << (i * 8);
            }
            data = &data[len_bytes..];

            // Parse offset delta (signed, sign-extended)
            let lcn = if offset_bytes == 0 {
                None // Sparse cluster run
            } else {
                let mut delta: i64 = 0;
                for i in 0..offset_bytes {
                    delta |= (data[i] as i64) << (i * 8);
                }
                // Sign extension
                if (data[offset_bytes - 1] & 0x80) != 0 {
                    for i in offset_bytes..8 {
                        delta |= (0xFFi64) << (i * 8);
                    }
                }
                prev_lcn += delta;
                data = &data[offset_bytes..];
                Some(prev_lcn as u64)
            };

            runs.push(DataRun {
                length_clusters,
                lcn,
            });
        }

        Ok(runs)
    }
}

/// Decoded $STANDARD_INFORMATION attribute
#[derive(Debug, Clone)]
pub struct StandardInformation {
    pub creation_time: Option<DateTime<Utc>>,
    pub alteration_time: Option<DateTime<Utc>>,
    pub mft_altered_time: Option<DateTime<Utc>>,
    pub read_time: Option<DateTime<Utc>>,
    pub dos_permissions: u32,
}

impl StandardInformation {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 36 {
            return Err(RecoveryError::BufferOutOfBounds {
                offset: 0,
                required: 36,
                available: data.len(),
            });
        }

        let mut reader = BinaryReader::new(data);
        let creation_ft = reader.read_u64_le()?;
        let alteration_ft = reader.read_u64_le()?;
        let mft_altered_ft = reader.read_u64_le()?;
        let read_ft = reader.read_u64_le()?;
        let dos_permissions = reader.read_u32_le()?;

        Ok(Self {
            creation_time: filetime_to_datetime(creation_ft),
            alteration_time: filetime_to_datetime(alteration_ft),
            mft_altered_time: filetime_to_datetime(mft_altered_ft),
            read_time: filetime_to_datetime(read_ft),
            dos_permissions,
        })
    }
}

/// Decoded $FILE_NAME attribute
#[derive(Debug, Clone)]
pub struct FileNameAttribute {
    pub parent_directory_record: u64,
    pub parent_directory_seq: u16,
    pub creation_time: Option<DateTime<Utc>>,
    pub alteration_time: Option<DateTime<Utc>>,
    pub allocated_size: u64,
    pub real_size: u64,
    pub flags: u32,
    pub namespace: u8,
    pub name: String,
}

impl FileNameAttribute {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 66 {
            return Err(RecoveryError::BufferOutOfBounds {
                offset: 0,
                required: 66,
                available: data.len(),
            });
        }

        let mut reader = BinaryReader::new(data);
        let parent_ref = reader.read_u64_le()?;
        let parent_record = parent_ref & 0x0000_FFFF_FFFF_FFFF;
        let parent_seq = (parent_ref >> 48) as u16;

        let creation_ft = reader.read_u64_le()?;
        let alteration_ft = reader.read_u64_le()?;
        let _mft_altered_ft = reader.read_u64_le()?;
        let _read_ft = reader.read_u64_le()?;
        let allocated_size = reader.read_u64_le()?;
        let real_size = reader.read_u64_le()?;
        let flags = reader.read_u32_le()?;
        let _reparse = reader.read_u32_le()?;
        let name_length = reader.read_u8()? as usize;
        let namespace = reader.read_u8()?;

        let name = reader.read_utf16_le_string(name_length)?;

        Ok(Self {
            parent_directory_record: parent_record,
            parent_directory_seq: parent_seq,
            creation_time: filetime_to_datetime(creation_ft),
            alteration_time: filetime_to_datetime(alteration_ft),
            allocated_size,
            real_size,
            flags,
            namespace,
            name,
        })
    }
}

#[derive(Debug, Clone)]
pub enum AttributeData {
    Resident(Vec<u8>),
    NonResident {
        allocated_size: u64,
        real_size: u64,
        data_runs: Vec<DataRun>,
    },
}

#[derive(Debug, Clone)]
pub struct NtfsAttribute {
    pub attr_type: AttributeType,
    pub record_length: u32,
    pub is_non_resident: bool,
    pub name: String,
    pub flags: u16,
    pub attribute_id: u16,
    pub data: AttributeData,
}

impl NtfsAttribute {
    pub fn parse(record_data: &[u8], offset: usize) -> Result<Option<Self>> {
        if offset + 4 > record_data.len() {
            return Ok(None);
        }

        let attr_type_raw = BinaryReader::peek_u32_le_at(record_data, offset)?;
        let attr_type = AttributeType::from_u32(attr_type_raw);
        if attr_type == AttributeType::EndMarker || attr_type_raw == 0 {
            return Ok(None);
        }

        if offset + 16 > record_data.len() {
            return Ok(None);
        }

        let mut reader = BinaryReader::new(&record_data[offset..]);
        reader.skip(4)?; // Skip attr_type
        let record_length = reader.read_u32_le()?;
        if record_length == 0 || offset + record_length as usize > record_data.len() {
            return Err(RecoveryError::NtfsError(format!(
                "Invalid attribute record length: {}",
                record_length
            )));
        }

        let non_resident_flag = reader.read_u8()?;
        let name_len = reader.read_u8()? as usize;
        let name_offset = reader.read_u16_le()? as usize;
        let flags = reader.read_u16_le()?;
        let attribute_id = reader.read_u16_le()?;

        let is_non_resident = non_resident_flag != 0;

        let name = if name_len > 0 && name_offset + (name_len * 2) <= record_length as usize {
            let mut name_reader = BinaryReader::new(&record_data[offset + name_offset..]);
            name_reader.read_utf16_le_string(name_len).unwrap_or_default()
        } else {
            String::new()
        };

        let data = if !is_non_resident {
            // Resident
            let value_length = reader.read_u32_le()? as usize;
            let value_offset = reader.read_u16_le()? as usize;

            let val_start = offset + value_offset;
            let val_end = val_start + value_length;
            if val_end <= offset + record_length as usize && val_end <= record_data.len() {
                AttributeData::Resident(record_data[val_start..val_end].to_vec())
            } else {
                AttributeData::Resident(Vec::new())
            }
        } else {
            // Non-Resident
            reader.skip(16)?; // Skip VCN range
            let runlist_offset = reader.read_u16_le()? as usize;
            reader.skip(6)?; // Compression
            let allocated_size = reader.read_u64_le()?;
            let real_size = reader.read_u64_le()?;

            let run_start = offset + runlist_offset;
            let run_bytes = if run_start < offset + record_length as usize {
                &record_data[run_start..offset + record_length as usize]
            } else {
                &[]
            };

            let data_runs = DataRun::parse_runlist(run_bytes).unwrap_or_default();
            AttributeData::NonResident {
                allocated_size,
                real_size,
                data_runs,
            }
        };

        Ok(Some(Self {
            attr_type,
            record_length,
            is_non_resident,
            name,
            flags,
            attribute_id,
            data,
        }))
    }
}
