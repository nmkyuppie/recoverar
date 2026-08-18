use crate::attribute::AttributeData;
use crate::mft::MftRecord;
use crate::vbr::NtfsVbr;
use disk_io::block_reader::BlockDevice;
use recovery_core::error::{RecoveryError, Result};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct NtfsNode {
    pub record_number: u64,
    pub parent_record: u64,
    pub name: String,
    pub is_directory: bool,
    pub is_in_use: bool,
    pub file_size: u64,
    pub children: Vec<u64>,
}

pub struct NtfsVolumeTree {
    pub vbr: NtfsVbr,
    pub partition_start_byte_offset: u64,
    pub nodes: HashMap<u64, NtfsNode>,
    pub records: HashMap<u64, MftRecord>,
}

fn sanitize_component(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '\0' => '_',
            c if c.is_control() => '_',
            _ => c,
        })
        .collect();
    let trimmed = cleaned.trim_matches(|c| c == ' ' || c == '.');
    if trimmed.is_empty() {
        "unnamed".to_string()
    } else {
        trimmed.to_string()
    }
}

impl NtfsVolumeTree {
    pub const ROOT_DIRECTORY_RECORD: u64 = 5;

    pub fn new(vbr: NtfsVbr, partition_start_byte_offset: u64) -> Self {
        Self {
            vbr,
            partition_start_byte_offset,
            nodes: HashMap::new(),
            records: HashMap::new(),
        }
    }

    /// Add a parsed MFT record into the tree.
    pub fn add_record(&mut self, record: MftRecord) {
        let fn_attr = record.file_name();
        let name = fn_attr
            .as_ref()
            .map(|f| f.name.clone())
            .unwrap_or_else(|| format!("Record_{}", record.record_number));
        let parent = fn_attr.as_ref().map(|f| f.parent_directory_record).unwrap_or(Self::ROOT_DIRECTORY_RECORD);
        let is_dir = record.is_directory;
        
        let size = if let Some(data) = record.data_attribute() {
            match &data.data {
                AttributeData::Resident(b) => b.len() as u64,
                AttributeData::NonResident { real_size, .. } => *real_size,
            }
        } else {
            fn_attr.as_ref().map(|f| f.real_size).unwrap_or(0)
        };

        self.nodes.insert(
            record.record_number,
            NtfsNode {
                record_number: record.record_number,
                parent_record: parent,
                name,
                is_directory: is_dir,
                is_in_use: record.is_in_use,
                file_size: size,
                children: Vec::new(),
            },
        );

        self.records.insert(record.record_number, record);
    }

    /// Build parent-child relationships across all registered nodes.
    pub fn build_hierarchy(&mut self) {
        let mut parent_to_children: HashMap<u64, Vec<u64>> = HashMap::new();

        for (rec_num, node) in &self.nodes {
            if *rec_num != node.parent_record {
                parent_to_children
                    .entry(node.parent_record)
                    .or_default()
                    .push(*rec_num);
            }
        }

        for (parent_num, children) in parent_to_children {
            if let Some(parent_node) = self.nodes.get_mut(&parent_num) {
                parent_node.children = children;
            }
        }
    }

    /// Get absolute reconstructed path for a given record number.
    pub fn get_path(&self, record_number: u64) -> PathBuf {
        let mut components = Vec::new();
        let mut current = record_number;
        let mut visited = std::collections::HashSet::new();

        while let Some(node) = self.nodes.get(&current) {
            if visited.contains(&current) {
                break; // Prevent infinite loop on circular references
            }
            visited.insert(current);

            if current == Self::ROOT_DIRECTORY_RECORD {
                break;
            }

            components.push(sanitize_component(&node.name));
            if node.parent_record == current {
                break;
            }
            current = node.parent_record;
        }

        components.reverse();
        if components.is_empty() {
            PathBuf::from(format!("Record_{}", record_number))
        } else {
            let mut p = PathBuf::new();
            for comp in components {
                p.push(comp);
            }
            p
        }
    }

    /// Extract a file stream to a destination path on the host system.
    pub fn extract_file<P: AsRef<Path>>(
        &self,
        device: &mut dyn BlockDevice,
        record_number: u64,
        dest_path: P,
    ) -> Result<u64> {
        let record = self.records.get(&record_number).ok_or_else(|| {
            RecoveryError::NtfsError(format!("MFT Record #{} not found", record_number))
        })?;

        let data_attr = record.data_attribute().ok_or_else(|| {
            RecoveryError::NtfsError(format!("No $DATA attribute found for record #{}", record_number))
        })?;

        let expected_size = match &data_attr.data {
            AttributeData::Resident(b) => b.len() as u64,
            AttributeData::NonResident { real_size, .. } => *real_size,
        };

        // If file already exists with expected size, skip re-extracting to save time
        if dest_path.as_ref().exists() {
            if let Ok(meta) = fs::metadata(dest_path.as_ref()) {
                if meta.len() == expected_size {
                    return Ok(expected_size);
                }
            }
        }

        if let Some(parent) = dest_path.as_ref().parent() {
            let _ = fs::create_dir_all(parent);
        }

        let mut out_file = match File::create(dest_path.as_ref()) {
            Ok(f) => f,
            Err(_) => {
                // Fallback to simple root path if deep path fails on Windows
                let fallback_name = format!("rec_{}_{}", record_number, sanitize_component(dest_path.as_ref().file_name().unwrap_or_default().to_str().unwrap_or("file")));
                let fallback_dir = dest_path.as_ref().parent().and_then(|p| p.parent()).unwrap_or_else(|| dest_path.as_ref());
                let fallback_path = fallback_dir.join(&fallback_name);
                File::create(&fallback_path)?
            }
        };

        let bytes_per_cluster = self.vbr.bytes_per_cluster() as usize;

        match &data_attr.data {
            AttributeData::Resident(bytes) => {
                out_file.write_all(bytes)?;
                Ok(bytes.len() as u64)
            }
            AttributeData::NonResident {
                real_size,
                data_runs,
                ..
            } => {
                let mut bytes_written = 0u64;
                let mut cluster_buf = vec![0u8; bytes_per_cluster];
                let sparse_cluster = vec![0u8; bytes_per_cluster];

                for run in data_runs {
                    for cluster_idx in 0..run.length_clusters {
                        if bytes_written >= *real_size {
                            break;
                        }

                        let bytes_to_copy = ((*real_size - bytes_written) as usize).min(bytes_per_cluster);

                        match run.lcn {
                            Some(base_lcn) => {
                                let lcn = base_lcn + cluster_idx;
                                let cluster_byte_offset = self.partition_start_byte_offset
                                    + (lcn * bytes_per_cluster as u64);

                                if device.read_exact_at(cluster_byte_offset, &mut cluster_buf).is_ok() {
                                    let _ = out_file.write_all(&cluster_buf[..bytes_to_copy]);
                                } else {
                                    // Zero-fill unreadable cluster
                                    let _ = out_file.write_all(&sparse_cluster[..bytes_to_copy]);
                                }
                            }
                            None => {
                                // Sparse run -> write zeros
                                let _ = out_file.write_all(&sparse_cluster[..bytes_to_copy]);
                            }
                        }

                        bytes_written += bytes_to_copy as u64;
                    }
                }

                Ok(bytes_written)
            }
        }
    }

    /// Extract all discovered files from this volume tree to a target directory, maintaining full folder paths.
    pub fn extract_all_files<P: AsRef<Path>, F>(
        &self,
        device: &mut dyn BlockDevice,
        output_dir: P,
        mut progress_cb: F,
    ) -> (usize, u64)
    where
        F: FnMut(usize, usize, &str, u64),
    {
        let files_to_extract: Vec<(u64, &NtfsNode)> = self
            .nodes
            .iter()
            .filter(|(id, n)| {
                !n.is_directory 
                    && !n.name.starts_with('$') 
                    && self.records.get(id).map(|r| r.data_attribute().is_some()).unwrap_or(false)
            })
            .map(|(id, n)| (*id, n))
            .collect();

        let total_files = files_to_extract.len();
        let mut total_bytes = 0u64;
        let mut extracted_count = 0;

        for (idx, (rec_num, node)) in files_to_extract.iter().enumerate() {
            let rel_path = self.get_path(*rec_num);
            let dest_path = output_dir.as_ref().join(&rel_path);

            match self.extract_file(device, *rec_num, &dest_path) {
                Ok(bytes) => {
                    total_bytes += bytes;
                    extracted_count += 1;
                    progress_cb(idx + 1, total_files, &node.name, bytes);
                }
                Err(_) => {
                    // Fallback to orphaned flat extraction
                    let flat_name = format!("orphaned_rec_{}_{}", rec_num, sanitize_component(&node.name));
                    let flat_path = output_dir.as_ref().join(&flat_name);
                    if let Ok(bytes) = self.extract_file(device, *rec_num, &flat_path) {
                        total_bytes += bytes;
                        extracted_count += 1;
                        progress_cb(idx + 1, total_files, &node.name, bytes);
                    }
                }
            }
        }

        (extracted_count, total_bytes)
    }
}
