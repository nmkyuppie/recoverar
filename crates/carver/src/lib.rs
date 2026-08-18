pub mod signatures;
pub mod scanner;

pub use signatures::{FileType, SignatureDef, FileValidator, SIGNATURE_REGISTRY};
pub use scanner::{CarveAlignment, CarvedFile, CarvingScanner};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_carve_jpeg_buffer() {
        let mut buffer = vec![0u8; 4096];
        // Inject JPEG at offset 512
        let jpeg_data = [
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46,
            0x00, 0x01, 0x01, 0x01, 0x00, 0x60, 0x00, 0x60, 0x00, 0x00,
            0xFF, 0xD9 // EOI
        ];
        buffer[512..512 + jpeg_data.len()].copy_from_slice(&jpeg_data);

        let scanner = CarvingScanner::new(CarveAlignment::Sector512);
        let results = scanner.scan_buffer(0, &buffer);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].file_type, FileType::Jpeg);
        assert_eq!(results[0].offset, 512);
        assert_eq!(results[0].size, jpeg_data.len());
    }

    #[test]
    fn test_carve_png_buffer() {
        let mut buffer = vec![0u8; 4096];
        // Inject PNG header + mock data + IEND chunk
        let mut png_data = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        png_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52]);
        png_data.extend_from_slice(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]); // IEND + CRC

        buffer[1024..1024 + png_data.len()].copy_from_slice(&png_data);

        let scanner = CarvingScanner::new(CarveAlignment::Sector512);
        let results = scanner.scan_buffer(0, &buffer);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].file_type, FileType::Png);
        assert_eq!(results[0].offset, 1024);
        assert_eq!(results[0].size, png_data.len());
    }

    #[test]
    fn test_carve_pdf_buffer() {
        let mut buffer = vec![0u8; 4096];
        let pdf_data = b"%PDF-1.4\n1 0 obj\n<< /Title (Test) >>\nendobj\n%%EOF\n";
        buffer[2048..2048 + pdf_data.len()].copy_from_slice(pdf_data);

        let scanner = CarvingScanner::new(CarveAlignment::Sector512);
        let results = scanner.scan_buffer(0, &buffer);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].file_type, FileType::Pdf);
        assert_eq!(results[0].offset, 2048);
        assert_eq!(results[0].size, pdf_data.len());
    }
}
