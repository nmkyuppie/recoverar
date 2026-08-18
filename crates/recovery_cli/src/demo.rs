use crc32fast::Hasher;
use recovery_core::error::Result;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub struct SyntheticDiskGenerator;

impl SyntheticDiskGenerator {
    /// Create a fully formatted synthetic disk image containing MBR, GPT, NTFS volume, and raw file payloads.
    pub fn create_test_image<P: AsRef<Path>>(path: P) -> Result<()> {
        let total_size: usize = 12 * 1024 * 1024; // 12 MB test disk
        let mut disk_data = vec![0u8; total_size];

        // 1. Write Protective MBR at LBA 0 (0..512)
        disk_data[510] = 0x55;
        disk_data[511] = 0xAA;
        // Disk signature
        disk_data[440..444].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        // Partition 1 (Protective GPT)
        disk_data[446] = 0x00; // Not bootable
        disk_data[450] = 0xEE; // GPT Protective
        disk_data[454..458].copy_from_slice(&1u32.to_le_bytes()); // Start LBA 1
        disk_data[458..462].copy_from_slice(&24575u32.to_le_bytes()); // Total sectors

        // 2. Write GPT Header at LBA 1 (512..1024)
        let gpt_hdr_offset = 512;
        disk_data[gpt_hdr_offset..gpt_hdr_offset + 8].copy_from_slice(b"EFI PART");
        disk_data[gpt_hdr_offset + 8..gpt_hdr_offset + 12].copy_from_slice(&0x00010000u32.to_le_bytes());
        disk_data[gpt_hdr_offset + 12..gpt_hdr_offset + 16].copy_from_slice(&92u32.to_le_bytes()); // Header size
        disk_data[gpt_hdr_offset + 24..gpt_hdr_offset + 32].copy_from_slice(&1u64.to_le_bytes()); // Current LBA 1
        disk_data[gpt_hdr_offset + 32..gpt_hdr_offset + 40].copy_from_slice(&24575u64.to_le_bytes()); // Backup LBA
        disk_data[gpt_hdr_offset + 40..gpt_hdr_offset + 48].copy_from_slice(&34u64.to_le_bytes()); // First usable LBA
        disk_data[gpt_hdr_offset + 48..gpt_hdr_offset + 56].copy_from_slice(&24542u64.to_le_bytes()); // Last usable LBA
        // Disk GUID
        disk_data[gpt_hdr_offset + 56..gpt_hdr_offset + 72].copy_from_slice(&[
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
        ]);
        disk_data[gpt_hdr_offset + 72..gpt_hdr_offset + 80].copy_from_slice(&2u64.to_le_bytes()); // Partition array LBA 2
        disk_data[gpt_hdr_offset + 80..gpt_hdr_offset + 84].copy_from_slice(&128u32.to_le_bytes()); // 128 entries
        disk_data[gpt_hdr_offset + 84..gpt_hdr_offset + 88].copy_from_slice(&128u32.to_le_bytes()); // 128 bytes each

        // 3. Write GPT Partition Array at LBA 2 (1024..17408)
        let gpt_array_offset = 1024;
        // Entry 1: Microsoft Basic Data (EBD0A0A2-B9E5-4433-87C0-68B6B72699C7)
        let part1_offset = gpt_array_offset;
        disk_data[part1_offset..part1_offset + 16].copy_from_slice(&[
            0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7
        ]);
        // Unique GUID
        disk_data[part1_offset + 16..part1_offset + 32].copy_from_slice(&[0x42; 16]);
        disk_data[part1_offset + 32..part1_offset + 40].copy_from_slice(&2048u64.to_le_bytes()); // Start LBA 2048 (1MB)
        disk_data[part1_offset + 40..part1_offset + 48].copy_from_slice(&10239u64.to_le_bytes()); // End LBA 10239 (5MB total)
        // Partition name: "Data Partition" in UTF-16LE
        let name_u16: Vec<u16> = "Data Partition".encode_utf16().collect();
        for (i, &ch) in name_u16.iter().enumerate() {
            disk_data[part1_offset + 56 + (i * 2)..part1_offset + 58 + (i * 2)].copy_from_slice(&ch.to_le_bytes());
        }

        // Calculate Partition Array CRC32
        let mut array_hasher = Hasher::new();
        array_hasher.update(&disk_data[gpt_array_offset..gpt_array_offset + (128 * 128)]);
        let array_crc = array_hasher.finalize();
        disk_data[gpt_hdr_offset + 88..gpt_hdr_offset + 92].copy_from_slice(&array_crc.to_le_bytes());

        // Calculate Header CRC32
        let mut hdr_crc_buf = disk_data[gpt_hdr_offset..gpt_hdr_offset + 92].to_vec();
        hdr_crc_buf[16..20].copy_from_slice(&[0, 0, 0, 0]);
        let mut hdr_hasher = Hasher::new();
        hdr_hasher.update(&hdr_crc_buf);
        let hdr_crc = hdr_hasher.finalize();
        disk_data[gpt_hdr_offset + 16..gpt_hdr_offset + 20].copy_from_slice(&hdr_crc.to_le_bytes());

        // 4. Write NTFS VBR at LBA 2048 (offset 1,048,576)
        let vbr_offset = 2048 * 512;
        disk_data[vbr_offset + 510] = 0x55;
        disk_data[vbr_offset + 511] = 0xAA;
        disk_data[vbr_offset + 3..vbr_offset + 11].copy_from_slice(b"NTFS    ");
        disk_data[vbr_offset + 11..vbr_offset + 13].copy_from_slice(&512u16.to_le_bytes()); // 512 B/sector
        disk_data[vbr_offset + 13] = 8; // 8 sectors/cluster (4096 B/cluster)
        disk_data[vbr_offset + 40..vbr_offset + 48].copy_from_slice(&8192u64.to_le_bytes()); // 8192 sectors
        disk_data[vbr_offset + 48..vbr_offset + 56].copy_from_slice(&4u64.to_le_bytes()); // $MFT starting cluster 4
        disk_data[vbr_offset + 56..vbr_offset + 64].copy_from_slice(&2u64.to_le_bytes()); // $MFTMirr cluster 2
        disk_data[vbr_offset + 64] = 0xF6; // -10 -> 1024 bytes per MFT record
        disk_data[vbr_offset + 68] = 0xF6;
        disk_data[vbr_offset + 72..vbr_offset + 80].copy_from_slice(&0xA1B2C3D4E5F60718u64.to_le_bytes());

        // 5. Write NTFS MFT Records at Cluster 4 (vbr_offset + 4 * 4096 = 1,048,576 + 16,384 = 1,064,960)
        let mft_start = vbr_offset + (4 * 4096);

        // Record 0: $MFT
        Self::write_sample_mft_record(
            &mut disk_data[mft_start..mft_start + 1024],
            0,
            "$MFT",
            5,
            false,
            b"Mock $MFT raw binary payload stream",
        );

        // Record 5: Root Directory (.)
        Self::write_sample_mft_record(
            &mut disk_data[mft_start + (5 * 1024)..mft_start + (6 * 1024)],
            5,
            ".",
            5,
            true,
            &[],
        );

        // Record 32: Test File "Critical_Report.txt"
        Self::write_sample_mft_record(
            &mut disk_data[mft_start + (32 * 1024)..mft_start + (33 * 1024)],
            32,
            "Critical_Report.txt",
            5,
            false,
            b"TOP SECRET DATA RECOVERY PAYLOAD: Hard disk blocks successfully recovered with 100% integrity.",
        );

        // 6. Embed Raw Carver Signatures in Unallocated Space (at 8 MB offset = 8,388,608)
        let carve_base = 8 * 1024 * 1024;

        // A. JPEG File at carve_base + 512
        let jpeg_offset = carve_base + 512;
        let jpeg_bytes = [
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x01,
            0x00, 0x60, 0x00, 0x60, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43, 0x00, 0x08, 0x06, 0x06,
            0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09, 0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D,
            0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12, 0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D,
            0x1A, 0x1C, 0x1C, 0x20, 0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28,
            0x37, 0x29, 0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32,
            0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x40, 0x00, 0x40,
            0x01, 0x01, 0x11, 0x00, 0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00,
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xFF, 0xD9, // End of Image
        ];
        disk_data[jpeg_offset..jpeg_offset + jpeg_bytes.len()].copy_from_slice(&jpeg_bytes);

        // B. PNG File at carve_base + 65536
        let png_offset = carve_base + 65536;
        let mut png_bytes = vec![
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // Signature
            0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR header
            0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x08, 0x06, 0x00, 0x00, 0x00,
            0x73, 0x7A, 0x7A, 0xF4, // IHDR CRC
        ];
        // Append IEND
        png_bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]);
        disk_data[png_offset..png_offset + png_bytes.len()].copy_from_slice(&png_bytes);

        // C. PDF File at carve_base + 131072
        let pdf_offset = carve_base + 131072;
        let pdf_bytes = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Count 1 >>\nendobj\nxref\n0 3\ntrailer\n<< /Size 3 >>\nstartxref\n112\n%%EOF\n";
        disk_data[pdf_offset..pdf_offset + pdf_bytes.len()].copy_from_slice(pdf_bytes);

        // D. ZIP Archive at carve_base + 196608
        let zip_offset = carve_base + 196608;
        let zip_bytes = [
            0x50, 0x4B, 0x03, 0x04, // Local header
            0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x08, 0x00, 0x00, 0x00, // File name length 8 ("test.txt")
            b't', b'e', b's', b't', b'.', b't', b'x', b't',
            // End of central dir
            0x50, 0x4B, 0x05, 0x06,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        disk_data[zip_offset..zip_offset + zip_bytes.len()].copy_from_slice(&zip_bytes);

        let mut file = File::create(path)?;
        file.write_all(&disk_data)?;
        file.flush()?;

        Ok(())
    }

    fn write_sample_mft_record(
        buf: &mut [u8],
        record_number: u64,
        name: &str,
        parent_rec: u64,
        is_dir: bool,
        content: &[u8],
    ) {
        // Clear record
        buf.fill(0);

        // Header
        buf[0..4].copy_from_slice(b"FILE");
        buf[4..6].copy_from_slice(&48u16.to_le_bytes()); // USA offset 48
        buf[6..8].copy_from_slice(&3u16.to_le_bytes());  // USA count 3
        buf[16..18].copy_from_slice(&1u16.to_le_bytes()); // Sequence 1
        buf[18..20].copy_from_slice(&1u16.to_le_bytes()); // Link count 1
        buf[20..22].copy_from_slice(&56u16.to_le_bytes()); // First attribute offset 56

        let flags: u16 = 0x0001 | if is_dir { 0x0002 } else { 0x0000 };
        buf[22..24].copy_from_slice(&flags.to_le_bytes());
        buf[44..48].copy_from_slice(&(record_number as u32).to_le_bytes());

        // USN array at 48
        let usn: u16 = 0x1234;
        buf[48..50].copy_from_slice(&usn.to_le_bytes());
        buf[50..52].copy_from_slice(&[0xAA, 0x55]); // Sector 1 end original
        buf[52..54].copy_from_slice(&[0x00, 0x00]); // Sector 2 end original

        let mut offset = 56;

        // 1. $STANDARD_INFORMATION (0x10)
        let si_len = 72;
        buf[offset..offset + 4].copy_from_slice(&0x10u32.to_le_bytes());
        buf[offset + 4..offset + 8].copy_from_slice(&(si_len as u32).to_le_bytes());
        buf[offset + 8] = 0; // Resident
        buf[offset + 16..offset + 20].copy_from_slice(&48u32.to_le_bytes()); // Value length
        buf[offset + 20..offset + 22].copy_from_slice(&24u16.to_le_bytes()); // Value offset
        // Timestamps (FILETIME 132539328000000000 = 2021-01-01)
        let ft = 132539328000000000u64;
        buf[offset + 24..offset + 32].copy_from_slice(&ft.to_le_bytes());
        buf[offset + 32..offset + 40].copy_from_slice(&ft.to_le_bytes());
        offset += si_len;

        // 2. $FILE_NAME (0x30)
        let name_u16: Vec<u16> = name.encode_utf16().collect();
        let name_bytes_len = name_u16.len() * 2;
        let fn_val_len = 66 + name_bytes_len;
        let fn_record_len = (24 + fn_val_len + 7) & !7; // 8-byte aligned

        buf[offset..offset + 4].copy_from_slice(&0x30u32.to_le_bytes());
        buf[offset + 4..offset + 8].copy_from_slice(&(fn_record_len as u32).to_le_bytes());
        buf[offset + 8] = 0; // Resident
        buf[offset + 16..offset + 20].copy_from_slice(&(fn_val_len as u32).to_le_bytes());
        buf[offset + 20..offset + 22].copy_from_slice(&24u16.to_le_bytes());

        let fn_val_start = offset + 24;
        let parent_ref = parent_rec | (1u64 << 48); // Sequence 1
        buf[fn_val_start..fn_val_start + 8].copy_from_slice(&parent_ref.to_le_bytes());
        buf[fn_val_start + 8..fn_val_start + 16].copy_from_slice(&ft.to_le_bytes());
        buf[fn_val_start + 40..fn_val_start + 48].copy_from_slice(&(content.len() as u64).to_le_bytes()); // Allocated
        buf[fn_val_start + 48..fn_val_start + 56].copy_from_slice(&(content.len() as u64).to_le_bytes()); // Real size
        buf[fn_val_start + 64] = name_u16.len() as u8;
        buf[fn_val_start + 65] = 1; // Win32 namespace

        for (i, &ch) in name_u16.iter().enumerate() {
            buf[fn_val_start + 66 + (i * 2)..fn_val_start + 68 + (i * 2)].copy_from_slice(&ch.to_le_bytes());
        }
        offset += fn_record_len;

        // 3. $DATA (0x80) (Resident)
        if !content.is_empty() {
            let data_val_len = content.len();
            let data_rec_len = (24 + data_val_len + 7) & !7;

            buf[offset..offset + 4].copy_from_slice(&0x80u32.to_le_bytes());
            buf[offset + 4..offset + 8].copy_from_slice(&(data_rec_len as u32).to_le_bytes());
            buf[offset + 8] = 0; // Resident
            buf[offset + 16..offset + 20].copy_from_slice(&(data_val_len as u32).to_le_bytes());
            buf[offset + 20..offset + 22].copy_from_slice(&24u16.to_le_bytes());
            buf[offset + 24..offset + 24 + data_val_len].copy_from_slice(content);
            offset += data_rec_len;
        }

        // End marker 0xFFFFFFFF
        buf[offset..offset + 4].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());

        // Place USN tag at end of sector 1 (510) and sector 2 (1022)
        buf[510..512].copy_from_slice(&usn.to_le_bytes());
        buf[1022..1024].copy_from_slice(&usn.to_le_bytes());
    }
}
