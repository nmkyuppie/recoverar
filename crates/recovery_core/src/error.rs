use thiserror::Error;

#[derive(Error, Debug)]
pub enum RecoveryError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Buffer out of bounds: required {required} bytes, but only {available} available at offset {offset}")]
    BufferOutOfBounds {
        offset: usize,
        required: usize,
        available: usize,
    },

    #[error("Invalid magic signature: expected '{expected}', found '{found}'")]
    InvalidSignature {
        expected: String,
        found: String,
    },

    #[error("Corrupted partition structure: {0}")]
    CorruptedPartition(String),

    #[error("CRC32 mismatch: expected {expected:#010X}, computed {computed:#010X}")]
    CrcMismatch {
        expected: u32,
        computed: u32,
    },

    #[error("Bad sector encountered at LBA {lba} (count: {count})")]
    BadSector {
        lba: u64,
        count: u64,
    },

    #[error("NTFS error: {0}")]
    NtfsError(String),

    #[error("USN Fixup verification failed at sector {sector_index}: expected {expected:#06X}, found {actual:#06X}")]
    FixupFailed {
        sector_index: usize,
        expected: u16,
        actual: u16,
    },

    #[error("Carver error: {0}")]
    CarverError(String),

    #[error("Generic recovery error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, RecoveryError>;
