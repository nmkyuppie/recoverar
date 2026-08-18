use crate::signatures::{FileType, FileValidator, SIGNATURE_REGISTRY};
use disk_io::block_reader::BlockDevice;
use rayon::prelude::*;
use recovery_core::error::Result;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarveAlignment {
    Sector512,
    Sector4096,
    ByteAligned,
}

impl CarveAlignment {
    pub fn step_bytes(&self) -> usize {
        match self {
            CarveAlignment::Sector512 => 512,
            CarveAlignment::Sector4096 => 4096,
            CarveAlignment::ByteAligned => 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CarvedFile {
    pub offset: u64,
    pub file_type: FileType,
    pub size: usize,
    pub is_validated: bool,
}

pub struct CarvingScanner {
    pub alignment: CarveAlignment,
    pub chunk_size: usize,
    pub max_file_size: usize,
}

impl Default for CarvingScanner {
    fn default() -> Self {
        Self {
            alignment: CarveAlignment::Sector512,
            chunk_size: 16 * 1024 * 1024, // 16 MB chunk for fast sequential USB reads
            max_file_size: 100 * 1024 * 1024, // 100 MB max carve
        }
    }
}

impl CarvingScanner {
    pub fn new(alignment: CarveAlignment) -> Self {
        Self {
            alignment,
            ..Default::default()
        }
    }

    /// Scan a raw byte buffer (in memory) for files.
    pub fn scan_buffer(&self, base_offset: u64, buffer: &[u8]) -> Vec<CarvedFile> {
        let step = self.alignment.step_bytes();
        let mut results = Vec::new();
        let mut i = 0;

        while i < buffer.len() {
            let slice = &buffer[i..];

            for sig in SIGNATURE_REGISTRY {
                if slice.len() >= sig.header_offset + sig.header_magic.len() {
                    let candidate = &slice[sig.header_offset..sig.header_offset + sig.header_magic.len()];
                    if candidate == sig.header_magic {
                        // Found matching header signature
                        let max_inspect = slice.len().min(sig.max_carve_size);
                        let sub_slice = &slice[..max_inspect];

                        if let Some(valid_size) = FileValidator::validate_and_calculate_size(sig.file_type, sub_slice) {
                            results.push(CarvedFile {
                                offset: base_offset + i as u64,
                                file_type: sig.file_type,
                                size: valid_size,
                                is_validated: true,
                            });
                            // Advance cursor to avoid overlapping duplicates
                            i += (valid_size / step).max(1) * step;
                            break;
                        }
                    }
                }
            }

            i += step;
        }

        results
    }

    /// Scan a block device across an offset range, instantly extracting carved files as they are found.
    pub fn scan_device_streaming<F, P>(
        &self,
        device: &mut dyn BlockDevice,
        start_offset: u64,
        scan_length: u64,
        output_dir: Option<P>,
        mut progress_cb: F,
    ) -> Result<Vec<CarvedFile>>
    where
        F: FnMut(u64, &[CarvedFile], Option<String>),
        P: AsRef<Path>,
    {
        let total_device_size = device.total_size();
        let end_offset = (start_offset + scan_length).min(total_device_size);
        let overlap = self.max_file_size.min(4 * 1024 * 1024); // 4 MB overlap
        let step_chunk = 8 * 1024 * 1024; // 8 MB sequential read

        let mut all_carved: Vec<CarvedFile> = Vec::new();
        let mut current_offset = start_offset;

        // If output_dir is given, create directory upfront
        if let Some(ref dir) = output_dir {
            fs::create_dir_all(dir)?;
        }

        // Read sequentially in high-speed 8MB batches, parallel process within batch
        while current_offset < end_offset {
            let read_len = ((end_offset - current_offset) as usize).min(step_chunk + overlap);
            let mut chunk_buf = vec![0u8; read_len];

            let mut newly_extracted_msg: Option<String> = None;

            if device.read_exact_at(current_offset, &mut chunk_buf).is_ok() {
                let sub_chunk_size = 2 * 1024 * 1024; // 2MB parallel slices
                let max_header_scan = sub_chunk_size;
                let sub_chunks: Vec<(usize, usize)> = (0..read_len)
                    .step_by(sub_chunk_size)
                    .map(|off| (off, (read_len - off).min(sub_chunk_size + overlap)))
                    .collect();

                let chunk_results: Vec<CarvedFile> = sub_chunks
                    .par_iter()
                    .flat_map(|&(rel_off, slice_len)| {
                        let sub_slice = &chunk_buf[rel_off..rel_off + slice_len];
                        let mut local_results = Vec::new();
                        let step = self.alignment.step_bytes();
                        let mut i = 0;
                        let scan_limit = sub_slice.len().min(max_header_scan);

                        while i < scan_limit {
                            let slice = &sub_slice[i..];
                            for sig in SIGNATURE_REGISTRY {
                                if slice.len() >= sig.header_offset + sig.header_magic.len() {
                                    let candidate = &slice[sig.header_offset..sig.header_offset + sig.header_magic.len()];
                                    if candidate == sig.header_magic {
                                        let max_inspect = slice.len().min(sig.max_carve_size);
                                        let sub = &slice[..max_inspect];
                                        if let Some(valid_size) = FileValidator::validate_and_calculate_size(sig.file_type, sub) {
                                            local_results.push(CarvedFile {
                                                offset: current_offset + rel_off as u64 + i as u64,
                                                file_type: sig.file_type,
                                                size: valid_size,
                                                is_validated: true,
                                            });
                                            i += (valid_size / step).max(1) * step;
                                            break;
                                        }
                                    }
                                }
                            }
                            i += step;
                        }
                        local_results
                    })
                    .collect();

                for item in chunk_results {
                    if !all_carved.iter().any(|existing| existing.offset == item.offset) {
                        if let Some(ref dir) = output_dir {
                            // Extract immediately in real-time
                            let type_dir = dir.as_ref().join(item.file_type.extension());
                            let _ = fs::create_dir_all(&type_dir);
                            let filename = format!("carved_0x{:012X}.{}", item.offset, item.file_type.extension());
                            let file_path = type_dir.join(&filename);

                            let rel_in_chunk = (item.offset - current_offset) as usize;
                            if rel_in_chunk + item.size <= chunk_buf.len() {
                                if let Ok(mut out) = File::create(&file_path) {
                                    let _ = out.write_all(&chunk_buf[rel_in_chunk..rel_in_chunk + item.size]);
                                    newly_extracted_msg = Some(format!(
                                        "Extracted {} ({} KB) to {}",
                                        item.file_type.extension().to_uppercase(),
                                        item.size / 1024,
                                        file_path.display()
                                    ));
                                }
                            }
                        }
                        all_carved.push(item);
                    }
                }
            }

            current_offset += step_chunk as u64;
            let scanned_so_far = current_offset.min(end_offset).saturating_sub(start_offset);
            progress_cb(scanned_so_far, &all_carved, newly_extracted_msg);
        }

        all_carved.sort_by_key(|f| f.offset);
        Ok(all_carved)
    }

    pub fn scan_device<F>(
        &self,
        device: &mut dyn BlockDevice,
        start_offset: u64,
        scan_length: u64,
        mut progress_cb: F,
    ) -> Result<Vec<CarvedFile>>
    where
        F: FnMut(u64, usize),
    {
        self.scan_device_streaming(
            device,
            start_offset,
            scan_length,
            None::<&str>,
            |cur, list, _| progress_cb(cur, list.len()),
        )
    }

    /// Extract a carved file to a destination directory.
    pub fn extract_carved_file<P: AsRef<Path>>(
        &self,
        device: &mut dyn BlockDevice,
        carved: &CarvedFile,
        output_dir: P,
    ) -> Result<String> {
        let type_dir = output_dir.as_ref().join(carved.file_type.extension());
        fs::create_dir_all(&type_dir)?;

        let filename = format!("carved_0x{:012X}.{}", carved.offset, carved.file_type.extension());
        let file_path = type_dir.join(&filename);

        let mut out = File::create(&file_path)?;
        let mut buffer = vec![0u8; carved.size];
        device.read_exact_at(carved.offset, &mut buffer)?;
        out.write_all(&buffer)?;

        Ok(file_path.to_string_lossy().to_string())
    }
}
