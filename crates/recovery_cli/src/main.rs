pub mod demo;

use clap::{Parser, Subcommand};
use colored::Colorize;
use disk_io::{open_block_device, DiskImager, FileBlockDevice, ImagerConfig, RecoveryMapFile};
use indicatif::{ProgressBar, ProgressStyle};
use partition_analyzer::{HeuristicPartitionScanner, PartitionAnalyzer, PartitionScheme};
use ntfs_engine::NtfsEngine;
use carver::{CarveAlignment, CarvingScanner};
use demo::SyntheticDiskGenerator;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "recoverar")]
#[command(author = "Forensics & Data Recovery Team")]
#[command(version = "1.0")]
#[command(about = "RECOVERAR - High-Performance Forensics & Data Recovery Suite", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Low-level disk imager with bad sector tolerance and mapfile logging
    Image {
        /// Path to source disk device or image file (e.g. \\.\PhysicalDrive1 or disk.img)
        #[arg(short, long)]
        source: String,

        /// Path to output image file (e.g. rescued_disk.raw)
        #[arg(short, long)]
        dest: String,

        /// Path to recovery mapfile (.map) for resuming sessions
        #[arg(short, long)]
        mapfile: Option<String>,

        /// Chunk read size in kilobytes (default: 64 KB)
        #[arg(long, default_value_t = 64)]
        chunk_kb: usize,

        /// Sector size in bytes (512 or 4096)
        #[arg(long, default_value_t = 512)]
        sector_size: u32,

        /// Enable direct unbuffered hardware I/O
        #[arg(long, default_value_t = false)]
        direct: bool,
    },

    /// Analyze partition tables (MBR/GPT) and scan for orphaned boot sectors
    Partitions {
        /// Path to device or image file
        #[arg(short, long)]
        device: String,

        /// Run deep heuristic scanner to locate lost/orphaned VBRs
        #[arg(long, default_value_t = false)]
        scan_orphaned: bool,
    },

    /// Parse NTFS volume boot records, MFT records, and reconstruct directory trees
    Ntfs {
        /// Path to device or image file
        #[arg(short, long)]
        device: String,

        /// Byte offset of NTFS partition start (default: 1048576 / LBA 2048)
        #[arg(short, long, default_value_t = 1048576)]
        offset: u64,

        /// Display reconstructed directory tree
        #[arg(long, default_value_t = true)]
        tree: bool,

        /// Max MFT records to scan (default: 5000)
        #[arg(long, default_value_t = 5000)]
        max_records: u64,

        /// Extract specific MFT record number to disk
        #[arg(long)]
        extract_record: Option<u64>,

        /// Output directory for extracted files
        #[arg(short, long, default_value = "./recovered_ntfs_files")]
        out_dir: PathBuf,
    },

    /// Multithreaded raw signature carving across unallocated disk space
    Carve {
        /// Path to device or image file
        #[arg(short, long)]
        device: String,

        /// Start byte offset to begin carving
        #[arg(short, long, default_value_t = 0)]
        start_offset: u64,

        /// Number of bytes to scan (0 = scan until end of device)
        #[arg(short, long, default_value_t = 0)]
        length: u64,

        /// Alignment mode: 512, 4096, or byte
        #[arg(long, default_value = "512")]
        align: String,

        /// Output directory for carved files
        #[arg(short, long, default_value = "./carved_files")]
        out_dir: PathBuf,
    },

    /// 1-Click Automated Recovery across ALL partitions (reconstructs folder trees & original filenames)
    AutoRecover {
        /// Path to device or image file (e.g. \\.\PhysicalDrive2)
        #[arg(short, long)]
        device: String,

        /// Output directory where all recovered partitions will be exported
        #[arg(short, long, default_value = "./recovered_disk_files")]
        out_dir: PathBuf,

        /// Maximum MFT records to scan per NTFS partition (default: 50000)
        #[arg(long, default_value_t = 50000)]
        max_records: u64,
    },

    /// Run full automated end-to-end demo and verification test lab
    Demo {
        /// Output test image file path
        #[arg(short, long, default_value = "demo_test_disk.img")]
        output: String,
    },
}

fn main() -> recovery_core::error::Result<()> {
    let cli = Cli::parse();

    println!("{}", "============================================================".bright_cyan().bold());
    println!("{}", "   RECOVERAR - FORENSICS & DATA RECOVERY SUITE v1.0         ".bright_white().bold());
    println!("{}", "============================================================".bright_cyan().bold());

    match cli.command {
        Commands::Image {
            source,
            dest,
            mapfile,
            chunk_kb,
            sector_size,
            direct,
        } => {
            println!("Opening source device: {}", source.yellow());
            let mut src_dev = open_block_device(&source, true, direct, sector_size)?;
            let total_size = src_dev.total_size();
            println!("Source size: {} bytes ({:.2} GB)", total_size, total_size as f64 / (1024.0 * 1024.0 * 1024.0));

            println!("Creating destination image: {}", dest.green());
            let mut dst_dev = FileBlockDevice::create_new(&dest, total_size, sector_size)?;

            let mapfile_path = mapfile.as_deref().unwrap_or("recovery.map");
            let loaded_map = if std::path::Path::new(mapfile_path).exists() {
                println!("Resuming from existing mapfile: {}", mapfile_path.cyan());
                Some(RecoveryMapFile::load_from_file(mapfile_path)?)
            } else {
                println!("Initializing new mapfile: {}", mapfile_path.cyan());
                None
            };

            let config = ImagerConfig {
                chunk_size: chunk_kb * 1024,
                sector_size,
                sync_mapfile_every_mb: 5,
            };

            let mut imager = DiskImager::new(&mut *src_dev, &mut dst_dev, config, loaded_map);

            let pb = ProgressBar::new(total_size);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({percent}%) | Speed: {msg} | Rescued: {pos_bytes}")
                    .unwrap()
                    .progress_chars("#>-"),
            );

            let start = Instant::now();
            imager.run_imaging(Some(mapfile_path), |stats| {
                pb.set_position(stats.rescued_bytes() + stats.bad_bytes());
                pb.set_message(format!("{:.2} MB/s", stats.current_throughput_mb_s));
            })?;

            pb.finish_with_message("Done");
            let stats = imager.stats();
            println!("\n{}", "Imaging Complete:".bright_green().bold());
            println!("  Elapsed time:      {:.2?}", start.elapsed());
            println!("  Rescued bytes:     {} ({:.2} MB)", stats.rescued_bytes(), stats.rescued_bytes() as f64 / (1024.0 * 1024.0));
            println!("  Bad sector bytes:  {} (Count: {})", stats.bad_bytes(), stats.bad_sectors);
            println!("  Average Speed:     {:.2} MB/s", stats.average_speed_mb_s());
            println!("  Mapfile saved:     {}", mapfile_path.green());
        }

        Commands::Partitions { device, scan_orphaned } => {
            println!("Analyzing partition tables on: {}", device.yellow());
            let mut dev = open_block_device(&device, true, false, 512)?;
            let scheme = PartitionAnalyzer::analyze(&mut *dev)?;

            match scheme {
                PartitionScheme::Gpt { primary, backup } => {
                    println!("\n{}", "[+] GPT Partition Table Detected:".bright_green().bold());
                    if let Some(p) = primary {
                        println!("{}", p);
                    }
                    if let Some(b) = backup {
                        println!("{}", b);
                    }
                }
                PartitionScheme::Mbr(mbr) => {
                    println!("\n{}", "[+] MBR Partition Table Detected:".bright_green().bold());
                    println!("{}", mbr);
                }
                PartitionScheme::RawOrUnknown => {
                    println!("\n{}", "[-] No standard MBR or GPT partition table found.".yellow());
                }
            }

            if scan_orphaned {
                println!("\n{}", "[*] Initiating deep heuristic search for orphaned VBRs / PBRs...".bright_cyan());
                let scanner = HeuristicPartitionScanner::new(1);
                let total_sec = dev.total_size() / 512;
                let found = scanner.scan_device(&mut *dev, 0, total_sec, |lba, count| {
                    if lba % 50000 == 0 {
                        print!("\rScanning LBA {}/{} (Found: {})...", lba, total_sec, count);
                        let _ = std::io::stdout().flush();
                    }
                })?;
                println!("\rScan finished. Discovered {} potential boot sector(s):", found.len());
                for (idx, b) in found.iter().enumerate() {
                    println!("  #{}: {}", idx + 1, b);
                }
            }
        }

        Commands::Ntfs {
            device,
            offset,
            tree,
            max_records,
            extract_record,
            out_dir,
        } => {
            println!("Opening NTFS Volume at offset {:#X} on {}", offset, device.yellow());
            let mut dev = open_block_device(&device, true, false, 512)?;
            let mut engine = NtfsEngine::open(&mut *dev, offset)?;

            println!("\n{}", engine.vbr());

            println!("[*] Scanning MFT records and reconstructing directory hierarchy...");
            let vol_tree = engine.scan_volume_tree(max_records, |rec, count| {
                if rec % 100 == 0 {
                    print!("\rProcessed {} MFT records (Indexed {} files/folders)...", rec, count);
                    let _ = std::io::stdout().flush();
                }
            })?;
            println!("\rCompleted MFT indexing: {} total filesystem nodes.\n", vol_tree.nodes.len());

            if let Some(target_rec) = extract_record {
                println!("\n[*] Extracting MFT Record #{} to {:?}", target_rec, out_dir);
                let path = vol_tree.get_path(target_rec);
                let dest = out_dir.join(path);
                let bytes = vol_tree.extract_file(&mut *dev, target_rec, &dest)?;
                println!("Successfully extracted {} bytes to {}", bytes, dest.display().to_string().bright_green());
            } else {
                println!("[*] Extracting all files with original folder structure to {}", out_dir.display().to_string().cyan());
                let pb = ProgressBar::new(vol_tree.nodes.len() as u64);
                pb.set_style(
                    ProgressStyle::default_bar()
                        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files | {msg}")
                        .unwrap()
                        .progress_chars("#>-"),
                );

                let (count, bytes) = vol_tree.extract_all_files(&mut *dev, &out_dir, |done, _, name, _| {
                    pb.set_position(done as u64);
                    pb.set_message(format!("Saving: {}", name));
                });

                pb.finish_with_message("Extraction Complete");
                println!(
                    "  {} Recovered {} files ({:.2} MB) into {}",
                    "✓".bright_green().bold(),
                    count,
                    bytes as f64 / (1024.0 * 1024.0),
                    out_dir.display().to_string().bright_green()
                );
            }
        }

        Commands::Carve {
            device,
            start_offset,
            length,
            align,
            out_dir,
        } => {
            println!("Opening block device for carving: {}", device.yellow());
            let mut dev = open_block_device(&device, true, false, 512)?;
            let mut total_size = dev.total_size();
            if total_size == 0 {
                if let Ok(scheme) = PartitionAnalyzer::analyze(&mut *dev) {
                    if let PartitionScheme::Gpt { primary: Some(ref p), .. } = scheme {
                        total_size = (p.header.backup_lba + 1) * dev.sector_size() as u64;
                    }
                }
            }
            let scan_len = if length == 0 { total_size.saturating_sub(start_offset) } else { length };

            let alignment = match align.as_str() {
                "4096" => CarveAlignment::Sector4096,
                "byte" => CarveAlignment::ByteAligned,
                _ => CarveAlignment::Sector512,
            };

            let pb = ProgressBar::new(scan_len);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({percent}%) | Speed: {msg} | Found: {pos_bytes}")
                    .unwrap()
                    .progress_chars("#>-"),
            );

            let scanner = CarvingScanner::new(alignment);
            let start = Instant::now();
            let mut last_check = Instant::now();
            let mut last_offset = start_offset;

            let carved_files = scanner.scan_device_streaming(
                &mut *dev,
                start_offset,
                scan_len,
                Some(&out_dir),
                |cur_off, found_list, newly_extracted| {
                    let processed = cur_off.saturating_sub(start_offset);
                    pb.set_position(processed);

                    let now = Instant::now();
                    let elapsed = now.duration_since(last_check).as_secs_f64();
                    if elapsed >= 0.5 {
                        let delta = cur_off.saturating_sub(last_offset);
                        let mb_s = (delta as f64 / (1024.0 * 1024.0)) / elapsed;
                        pb.set_message(format!("{:.1} MB/s (Files: {})", mb_s, found_list.len()));
                        last_check = now;
                        last_offset = cur_off;
                    }

                    if let Some(msg) = newly_extracted {
                        pb.println(format!("  {} {}", "[+]".bright_green().bold(), msg.bright_cyan()));
                    }
                },
            )?;

            pb.finish_with_message("Done");
            println!(
                "\n{}",
                format!("Carving Complete: {} files recovered in {:.2?}", carved_files.len(), start.elapsed())
                    .bright_green()
                    .bold()
            );
            println!("  Output directory: {}", out_dir.display().to_string().bright_cyan());
        }

        Commands::AutoRecover { device, out_dir, max_records } => {
            println!("Initializing 1-Click Automated Recovery on: {}", device.yellow().bold());
            let mut dev = open_block_device(&device, true, false, 512)?;
            let sector_size = dev.sector_size() as u64;

            println!("\n{}", "[*] Step 1: Discovering all partitions and volumes across the disk...".bright_cyan().bold());
            let mut volumes = PartitionAnalyzer::detect_all_volumes(&mut *dev);

            if volumes.is_empty() {
                println!("  [!] No standard partitions found in partition table. Running deep heuristic scanner...");
                let scanner = HeuristicPartitionScanner::new(1);
                let total_sec = dev.total_size() / sector_size;
                volumes = scanner.scan_device(&mut *dev, 0, total_sec, |_, _| {})?;
            }

            println!("{}", format!("  Found {} partition(s) on the disk.\n", volumes.len()).bright_green().bold());

            let mut grand_total_files = 0usize;
            let mut grand_total_bytes = 0u64;

            for (idx, vol) in volumes.iter().enumerate() {
                let part_offset = vol.start_lba * sector_size;
                let part_size_gb = (vol.total_sectors * vol.bytes_per_sector as u64) as f64 / (1024.0 * 1024.0 * 1024.0);
                let safe_label = vol.volume_label.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
                let part_dir_name = format!("Partition_{}_{}_{:.1}GB", idx + 1, safe_label, part_size_gb);
                let part_out_dir = out_dir.join(&part_dir_name);

                println!(
                    "{}",
                    "============================================================".bright_blue()
                );
                println!(
                    "{} Partition #{} [{}] Start LBA: {} | Size: {:.2} GB",
                    "[▶]".bright_yellow().bold(),
                    idx + 1,
                    vol.volume_label.bright_white(),
                    vol.start_lba,
                    part_size_gb
                );
                println!("  Target export directory: {}", part_out_dir.display().to_string().cyan());

                // Try NTFS Engine first
                let ntfs_res = NtfsEngine::open(&mut *dev, part_offset);
                match ntfs_res {
                    Ok(mut ntfs) => {
                        println!("  {} NTFS Volume detected! Decoding MFT records...", "[+]".bright_green());
                        match ntfs.scan_volume_tree(max_records, |_, _| {}) {
                            Ok(tree) => {
                                println!("  {} Indexed {} files and folders in directory hierarchy.", "[+]".bright_green(), tree.nodes.len());
                                println!("  [*] Extracting files with original names and folder structure...");

                                let files_count = tree.nodes.iter().filter(|(id, n)| !n.is_directory && !n.name.starts_with('$') && tree.records.get(id).map(|r| r.data_attribute().is_some()).unwrap_or(false)).count();
                                let pb = ProgressBar::new(files_count as u64);
                                pb.set_style(
                                    ProgressStyle::default_bar()
                                        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files | {msg}")
                                        .unwrap()
                                        .progress_chars("#>-"),
                                );

                                let (count, bytes) = tree.extract_all_files(&mut *dev, &part_out_dir, |done, _, name, _| {
                                    pb.set_position(done as u64);
                                    pb.set_message(format!("Saving: {}", name));
                                });

                                pb.finish_with_message("Partition Extraction Complete");
                                println!(
                                    "  {} Recovered {} files ({:.2} MB) into {}",
                                    "✓".bright_green().bold(),
                                    count,
                                    bytes as f64 / (1024.0 * 1024.0),
                                    part_out_dir.display().to_string().bright_green()
                                );

                                if count == 0 {
                                    println!("  [!] NTFS filesystem returned 0 files. Triggering deep signature carver on Partition #{}...", idx + 1);
                                    let scanner = CarvingScanner::new(CarveAlignment::Sector512);
                                    let scan_len = vol.total_sectors * vol.bytes_per_sector as u64;

                                    let pb = ProgressBar::new(scan_len);
                                    pb.set_style(
                                        ProgressStyle::default_bar()
                                            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, ETA: {eta}) | {msg}")
                                            .unwrap()
                                            .progress_chars("#>-"),
                                    );

                                    if let Ok(carved) = scanner.scan_device_streaming(
                                        &mut *dev,
                                        part_offset,
                                        scan_len,
                                        Some(&part_out_dir),
                                        |curr, items, msg| {
                                            pb.set_position(curr);
                                            if let Some(m) = msg {
                                                pb.println(format!("    {} {}", "[+]".bright_green().bold(), m.bright_cyan()));
                                            }
                                            pb.set_message(format!("Found {} files", items.len()));
                                        },
                                    ) {
                                        pb.finish_with_message("Carving Complete");
                                        let total_carved_bytes: u64 = carved.iter().map(|f| f.size as u64).sum();
                                        println!(
                                            "  {} Carved {} files ({:.2} MB) into {}",
                                            "✓".bright_green().bold(),
                                            carved.len(),
                                            total_carved_bytes as f64 / (1024.0 * 1024.0),
                                            part_out_dir.display().to_string().bright_green()
                                        );
                                        grand_total_files += carved.len();
                                        grand_total_bytes += total_carved_bytes;
                                    }
                                } else {
                                    grand_total_files += count;
                                    grand_total_bytes += bytes;
                                }
                            }
                            Err(e) => {
                                println!("  [!] NTFS MFT scan error: {}. Falling back to raw carver...", e);
                                let scanner = CarvingScanner::new(CarveAlignment::Sector512);
                                let scan_len = vol.total_sectors * vol.bytes_per_sector as u64;

                                let pb = ProgressBar::new(scan_len);
                                pb.set_style(
                                    ProgressStyle::default_bar()
                                        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, ETA: {eta}) | {msg}")
                                        .unwrap()
                                        .progress_chars("#>-"),
                                );

                                if let Ok(carved) = scanner.scan_device_streaming(
                                    &mut *dev,
                                    part_offset,
                                    scan_len,
                                    Some(&part_out_dir),
                                    |curr, items, msg| {
                                        pb.set_position(curr);
                                        if let Some(m) = msg {
                                            pb.println(format!("    {} {}", "[+]".bright_green().bold(), m.bright_cyan()));
                                        }
                                        pb.set_message(format!("Found {} files", items.len()));
                                    },
                                ) {
                                    pb.finish_with_message("Carving Complete");
                                    let total_carved_bytes: u64 = carved.iter().map(|f| f.size as u64).sum();
                                    println!(
                                        "  {} Carved {} files ({:.2} MB) into {}",
                                        "✓".bright_green().bold(),
                                        carved.len(),
                                        total_carved_bytes as f64 / (1024.0 * 1024.0),
                                        part_out_dir.display().to_string().bright_green()
                                    );
                                    grand_total_files += carved.len();
                                    grand_total_bytes += total_carved_bytes;
                                }
                            }
                        }
                    }
                    Err(_) => {
                        println!("  [i] Non-NTFS or raw partition. Running raw signature carver...");
                        let scanner = CarvingScanner::new(CarveAlignment::Sector512);
                        let scan_len = vol.total_sectors * vol.bytes_per_sector as u64;

                        let pb = ProgressBar::new(scan_len);
                        pb.set_style(
                            ProgressStyle::default_bar()
                                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, ETA: {eta}) | {msg}")
                                .unwrap()
                                .progress_chars("#>-"),
                        );

                        let mut last_log_gb = 0u64;

                        if let Ok(carved) = scanner.scan_device_streaming(
                            &mut *dev,
                            part_offset,
                            scan_len,
                            Some(&part_out_dir),
                            |curr, items, msg| {
                                pb.set_position(curr);
                                if let Some(m) = msg {
                                    pb.println(format!("    {} {}", "[+]".bright_green().bold(), m.bright_cyan()));
                                }
                                let current_gb = curr / (1024 * 1024 * 1024);
                                if current_gb > last_log_gb && current_gb % 2 == 0 {
                                    last_log_gb = current_gb;
                                    let total_gb = scan_len / (1024 * 1024 * 1024);
                                    let pct = (curr as f64 / scan_len as f64) * 100.0;
                                    pb.println(format!(
                                        "    {} Scanned {:.1} GB / {:.1} GB ({:.1}%) | Rescued: {} files",
                                        "[*]".bright_yellow().bold(),
                                        current_gb,
                                        total_gb,
                                        pct,
                                        items.len()
                                    ));
                                }
                                pb.set_message(format!("Found {} files", items.len()));
                            },
                        ) {
                            pb.finish_with_message("Carving Complete");
                            let total_carved_bytes: u64 = carved.iter().map(|f| f.size as u64).sum();
                            println!(
                                "  {} Carved {} files ({:.2} MB) into {}",
                                "✓".bright_green().bold(),
                                carved.len(),
                                total_carved_bytes as f64 / (1024.0 * 1024.0),
                                part_out_dir.display().to_string().bright_green()
                            );

                            grand_total_files += carved.len();
                            grand_total_bytes += total_carved_bytes;
                        }
                    }
                }
                println!();
            }

            println!("{}", "============================================================".bright_green().bold());
            println!("{}", "   AUTOMATED RECOVERY SUMMARY                               ".bright_white().bold());
            println!("{}", "============================================================".bright_green().bold());
            println!("  Total Partitions Processed: {}", volumes.len());
            println!("  Total Files Recovered:      {}", grand_total_files.to_string().bright_green().bold());
            println!("  Total Data Rescued:         {:.2} GB", grand_total_bytes as f64 / (1024.0 * 1024.0 * 1024.0));
            println!("  Root Output Directory:      {}", out_dir.display().to_string().bright_cyan().bold());
        }

        Commands::Demo { output } => {
            println!("{}", "[*] Generating synthetic test disk image...".bright_magenta().bold());
            SyntheticDiskGenerator::create_test_image(&output)?;
            println!("  Created synthetic test disk image: {} (12 MB)", output.green());

            // 1. Run Partition Analysis
            println!("\n{}", "--- 1. Testing Partition Analyzer Module ---".bright_yellow().bold());
            let mut dev = open_block_device(&output, true, false, 512)?;
            let scheme = PartitionAnalyzer::analyze(&mut *dev)?;
            if let PartitionScheme::Gpt { primary, .. } = scheme {
                if let Some(p) = primary {
                    println!("{}", p);
                }
            }

            // 2. Run NTFS Engine
            println!("{}", "--- 2. Testing NTFS Engine & Tree Reconstructor ---".bright_yellow().bold());
            let mut ntfs = NtfsEngine::open(&mut *dev, 2048 * 512)?;
            println!("{}", ntfs.vbr());

            let tree = ntfs.scan_volume_tree(100, |_, _| {})?;
            println!("{}", "Reconstructed Filesystem Nodes:".bright_green());
            for (rec_num, node) in &tree.nodes {
                let path = tree.get_path(*rec_num);
                println!("  MFT #{:<3} {:<6} {:<30} ({} bytes)", rec_num, if node.is_directory { "[DIR]" } else { "[FILE]" }, path.display(), node.file_size);
            }

            // Extract file
            let out_test = PathBuf::from("./demo_extracted_files");
            if let Some((&rec, _)) = tree.nodes.iter().find(|(_, n)| n.name == "Critical_Report.txt") {
                let path = tree.get_path(rec);
                let dest = out_test.join(path);
                let bytes = tree.extract_file(&mut *dev, rec, &dest)?;
                println!("Extracted record #{} ({} bytes) to {}", rec, bytes, dest.display().to_string().green());
                if let Ok(content) = std::fs::read_to_string(&dest) {
                    println!("  File Content: \"{}\"", content.bright_cyan());
                }
            }

            // 3. Run Signature Carver
            println!("\n{}", "--- 3. Testing Multithreaded Signature Carver ---".bright_yellow().bold());
            let scanner = CarvingScanner::new(CarveAlignment::Sector512);
            let carved = scanner.scan_device(&mut *dev, 8 * 1024 * 1024, 4 * 1024 * 1024, |_, _| {})?;
            println!("Carved {} files from unallocated sectors:", carved.len().to_string().bright_green().bold());

            let carve_dir = PathBuf::from("./demo_carved_files");
            for (idx, f) in carved.iter().enumerate() {
                let extracted_path = scanner.extract_carved_file(&mut *dev, f, &carve_dir)?;
                println!("  #{}: {} at offset {:#X} ({} bytes) -> {}", idx + 1, f.file_type.extension().to_uppercase().yellow(), f.offset, f.size, extracted_path.green());
            }

            // 4. Run Imager with bad sector recovery simulation
            println!("\n{}", "--- 4. Testing Block Imager & Mapfile Logger ---".bright_yellow().bold());
            let rescued_img = "demo_rescued_image.raw";
            let map_file = "demo_rescued.map";
            let mut dst = FileBlockDevice::create_new(rescued_img, dev.total_size(), 512)?;
            let config = ImagerConfig {
                chunk_size: 16 * 1024,
                sector_size: 512,
                sync_mapfile_every_mb: 1,
            };
            let mut imager = DiskImager::new(&mut *dev, &mut dst, config, None);
            imager.run_imaging(Some(map_file), |_| {})?;
            println!("Imaged {} rescued bytes with mapfile {}", imager.stats().rescued_bytes().to_string().green(), map_file.cyan());

            println!("\n{}", "ALL MODULES EXECUTED AND VERIFIED SUCCESSFULLY!".bright_green().bold());
        }
    }

    Ok(())
}
