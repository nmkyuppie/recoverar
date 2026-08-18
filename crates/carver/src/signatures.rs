use recovery_core::binary_reader::BinaryReader;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    Jpeg,
    Png,
    Pdf,
    Zip,
    Mp4,
    Mkv,
    Avi,
    Gif,
}

impl FileType {
    pub fn extension(&self) -> &'static str {
        match self {
            FileType::Jpeg => "jpg",
            FileType::Png => "png",
            FileType::Pdf => "pdf",
            FileType::Zip => "zip",
            FileType::Mp4 => "mp4",
            FileType::Mkv => "mkv",
            FileType::Avi => "avi",
            FileType::Gif => "gif",
        }
    }

    pub fn mime_type(&self) -> &'static str {
        match self {
            FileType::Jpeg => "image/jpeg",
            FileType::Png => "image/png",
            FileType::Pdf => "application/pdf",
            FileType::Zip => "application/zip",
            FileType::Mp4 => "video/mp4",
            FileType::Mkv => "video/x-matroska",
            FileType::Avi => "video/x-msvideo",
            FileType::Gif => "image/gif",
        }
    }
}

impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.extension().to_uppercase())
    }
}

pub struct SignatureDef {
    pub file_type: FileType,
    pub header_magic: &'static [u8],
    pub header_offset: usize,
    pub max_carve_size: usize,
}

pub const SIGNATURE_REGISTRY: &[SignatureDef] = &[
    // JPEG
    SignatureDef {
        file_type: FileType::Jpeg,
        header_magic: &[0xFF, 0xD8, 0xFF],
        header_offset: 0,
        max_carve_size: 50 * 1024 * 1024, // 50 MB
    },
    // PNG
    SignatureDef {
        file_type: FileType::Png,
        header_magic: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        header_offset: 0,
        max_carve_size: 50 * 1024 * 1024,
    },
    // PDF
    SignatureDef {
        file_type: FileType::Pdf,
        header_magic: b"%PDF-",
        header_offset: 0,
        max_carve_size: 100 * 1024 * 1024, // 100 MB
    },
    // ZIP / Office XML (DOCX, XLSX, PPTX)
    SignatureDef {
        file_type: FileType::Zip,
        header_magic: &[0x50, 0x4B, 0x03, 0x04],
        header_offset: 0,
        max_carve_size: 500 * 1024 * 1024, // 500 MB
    },
    // MP4 / MOV Video (ftyp signature at offset 4)
    SignatureDef {
        file_type: FileType::Mp4,
        header_magic: b"ftyp",
        header_offset: 4,
        max_carve_size: 5 * 1024 * 1024 * 1024, // 5 GB
    },
    // MKV / WebM Video (Matroska EBML)
    SignatureDef {
        file_type: FileType::Mkv,
        header_magic: &[0x1A, 0x45, 0xDF, 0xA3],
        header_offset: 0,
        max_carve_size: 10 * 1024 * 1024 * 1024, // 10 GB
    },
    // AVI Video (RIFF....AVI )
    SignatureDef {
        file_type: FileType::Avi,
        header_magic: b"RIFF",
        header_offset: 0,
        max_carve_size: 5 * 1024 * 1024 * 1024, // 5 GB
    },
    // GIF87a / GIF89a
    SignatureDef {
        file_type: FileType::Gif,
        header_magic: b"GIF8",
        header_offset: 0,
        max_carve_size: 30 * 1024 * 1024,
    },
];

pub struct FileValidator;

impl FileValidator {
    /// Inspect buffer at header match and determine the valid file size / end boundary.
    pub fn validate_and_calculate_size(file_type: FileType, data: &[u8]) -> Option<usize> {
        match file_type {
            FileType::Jpeg => Self::validate_jpeg(data),
            FileType::Png => Self::validate_png(data),
            FileType::Pdf => Self::validate_pdf(data),
            FileType::Zip => Self::validate_zip(data),
            FileType::Mp4 => Self::validate_mp4(data),
            FileType::Mkv => Self::validate_mkv(data),
            FileType::Avi => Self::validate_avi(data),
            FileType::Gif => Self::validate_gif(data),
        }
    }

    fn validate_jpeg(data: &[u8]) -> Option<usize> {
        if data.len() < 4 || &data[0..3] != [0xFF, 0xD8, 0xFF] {
            return None;
        }

        // Search for End of Image marker 0xFF, 0xD9
        // Skip initial bytes
        let mut i = 3;
        while i + 1 < data.len() && i < 50 * 1024 * 1024 {
            if data[i] == 0xFF && data[i + 1] == 0xD9 {
                return Some(i + 2);
            }
            i += 1;
        }
        None
    }

    fn validate_png(data: &[u8]) -> Option<usize> {
        if data.len() < 8 || &data[0..8] != [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
            return None;
        }

        // Look for IEND chunk: "IEND" (49 45 4E 44) + 4-byte CRC (AE 42 60 82)
        let iend_pattern = &[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82];
        if let Some(pos) = data.windows(iend_pattern.len()).position(|w| w == iend_pattern) {
            return Some(pos + iend_pattern.len());
        }
        None
    }

    fn validate_pdf(data: &[u8]) -> Option<usize> {
        if data.len() < 8 || &data[0..5] != b"%PDF-" {
            return None;
        }

        // %%EOF is always near the end of the file/stream
        let eof_pattern = b"%%EOF";
        let search_start = data.len().saturating_sub(4096);
        let tail = &data[search_start..];

        for (idx, window) in tail.windows(eof_pattern.len()).enumerate() {
            if window == eof_pattern {
                let mut end = search_start + idx + eof_pattern.len();
                while end < data.len() && (data[end] == b'\r' || data[end] == b'\n') {
                    end += 1;
                }
                return Some(end);
            }
        }
        
        // Fallback: if not found in last 4KB, check full buffer with fast stride
        for (idx, window) in data.windows(eof_pattern.len()).enumerate().step_by(1) {
            if window == eof_pattern {
                let mut end = idx + eof_pattern.len();
                while end < data.len() && (data[end] == b'\r' || data[end] == b'\n') {
                    end += 1;
                }
                return Some(end);
            }
        }
        None
    }

    fn validate_zip(data: &[u8]) -> Option<usize> {
        if data.len() < 30 || &data[0..4] != [0x50, 0x4B, 0x03, 0x04] {
            return None;
        }

        // End of Central Directory Record (EOCD) is in the last 65KB + 22 bytes
        let eocd_sig = &[0x50, 0x4B, 0x05, 0x06];
        let search_start = data.len().saturating_sub(65536 + 22);
        let tail = &data[search_start..];

        for (idx, window) in tail.windows(eocd_sig.len()).enumerate() {
            if window == eocd_sig {
                let abs_idx = search_start + idx;
                if abs_idx + 22 <= data.len() {
                    let comment_len = BinaryReader::peek_u16_le_at(data, abs_idx + 20).unwrap_or(0) as usize;
                    let total_end = abs_idx + 22 + comment_len;
                    if total_end <= data.len() {
                        return Some(total_end);
                    }
                }
            }
        }
        None
    }

    fn validate_mp4(data: &[u8]) -> Option<usize> {
        if data.len() < 12 {
            return None;
        }

        // Check if 4..8 is 'ftyp'
        if &data[4..8] != b"ftyp" {
            return None;
        }

        // Parse box atom tree
        let mut offset = 0;
        while offset + 8 <= data.len() {
            let size = BinaryReader::peek_u32_be_at(data, offset).ok()? as usize;
            if size == 0 {
                // Extends to EOF
                return Some(data.len());
            } else if size == 1 {
                // 64-bit extended size
                if offset + 16 > data.len() {
                    break;
                }
                let ext_size = BinaryReader::peek_u64_be_at(data, offset + 8).ok()? as usize;
                if ext_size < 16 {
                    break;
                }
                offset += ext_size;
            } else if size < 8 {
                break;
            } else {
                offset += size;
            }

            if offset >= data.len() {
                return Some(data.len());
            }
        }

        if offset > 8 {
            Some(offset)
        } else {
            None
        }
    }

    fn validate_mkv(data: &[u8]) -> Option<usize> {
        if data.len() < 4 || &data[0..4] != [0x1A, 0x45, 0xDF, 0xA3] {
            return None;
        }

        // Matroska EBML container - if size is not easily bounded, return up to 5GB or buffer slice
        let max_len = data.len().min(5 * 1024 * 1024 * 1024);
        Some(max_len)
    }

    fn validate_avi(data: &[u8]) -> Option<usize> {
        if data.len() < 12 || &data[0..4] != b"RIFF" || &data[8..12] != b"AVI " {
            return None;
        }

        let riff_size = BinaryReader::peek_u32_le_at(data, 4).ok()? as usize;
        let total_size = riff_size + 8;
        if total_size <= data.len() {
            Some(total_size)
        } else {
            Some(data.len())
        }
    }

    fn validate_gif(data: &[u8]) -> Option<usize> {
        if data.len() < 6 || (&data[0..6] != b"GIF87a" && &data[0..6] != b"GIF89a") {
            return None;
        }

        // Search for GIF trailer 0x3B
        for i in 6..data.len() {
            if data[i] == 0x3B {
                return Some(i + 1);
            }
        }
        None
    }
}
