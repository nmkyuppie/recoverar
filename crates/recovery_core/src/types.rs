use std::fmt;
use chrono::{DateTime, Utc, TimeZone};

/// Common disk sector size
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectorSize {
    Standard512 = 512,
    Advanced4096 = 4096,
}

impl SectorSize {
    pub const fn as_usize(self) -> usize {
        self as usize
    }

    pub const fn as_u64(self) -> u64 {
        self as u64
    }

    pub fn from_bytes(bytes: u32) -> Option<Self> {
        match bytes {
            512 => Some(SectorSize::Standard512),
            4096 => Some(SectorSize::Advanced4096),
            _ => None,
        }
    }
}

/// Logical Block Address representation
pub type Lba = u64;

/// Cluster number representation
pub type Cluster = u64;

/// Byte offset & size range
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    pub start: u64,
    pub length: u64,
}

impl ByteRange {
    pub const fn new(start: u64, length: u64) -> Self {
        Self { start, length }
    }

    pub const fn end(&self) -> u64 {
        self.start + self.length
    }
}

/// 128-bit GUID for GPT partition entries and NTFS objects
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    pub const fn from_raw(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self {
            data1,
            data2,
            data3,
            data4,
        }
    }

    pub fn from_bytes_le(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 16 {
            return None;
        }
        let data1 = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let data2 = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
        let data3 = u16::from_le_bytes(bytes[6..8].try_into().unwrap());
        let mut data4 = [0u8; 8];
        data4.copy_from_slice(&bytes[8..16]);
        Some(Self {
            data1,
            data2,
            data3,
            data4,
        })
    }

    pub fn is_zero(&self) -> bool {
        self.data1 == 0 && self.data2 == 0 && self.data3 == 0 && self.data4 == [0u8; 8]
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7]
        )
    }
}

/// Convert Windows FILETIME (100-nanosecond intervals since Jan 1, 1601 UTC) to chrono DateTime<Utc>
pub fn filetime_to_datetime(filetime: u64) -> Option<DateTime<Utc>> {
    if filetime == 0 {
        return None;
    }
    // 116444736000000000 = intervals between 1601-01-01 and 1970-01-01
    const EPOCH_DIFFERENCE: u64 = 116_444_736_000_000_000;
    if filetime < EPOCH_DIFFERENCE {
        return None;
    }
    let nanos_since_unix = (filetime - EPOCH_DIFFERENCE) * 100;
    let secs = (nanos_since_unix / 1_000_000_000) as i64;
    let nsecs = (nanos_since_unix % 1_000_000_000) as u32;

    Utc.timestamp_opt(secs, nsecs).single()
}
