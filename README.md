# Recoverar 🛡️
### High-Performance Storage Forensics & Universal Data Recovery Suite

**Recoverar** is a blazingly fast, multi-threaded storage forensics and data recovery engine written in modern Rust. It is engineered for recovering data from damaged hard drives, corrupted partitions, formatted storage devices, and raw disk images.

Unlike traditional tools that either rely solely on slow raw carving or fail when partition tables are corrupted, **Recoverar** combines **direct Master File Table ($MFT) structural reconstruction** with **multi-threaded Rayon signature carving**, bad sector tolerance, and smart multi-partition auto-discovery.

---

## 🌟 Key Capabilities

- ⚡ **1-Click Universal Auto-Recovery (`auto-recover`)**: Automatically detects all partitions (MBR, GPT, and EBR extended logical chains) across any physical drive or image file, reconstructing full folder hierarchies and original filenames.
- 🌳 **Direct NTFS MFT Engine (`ntfs`)**: Bypasses operating system file locks and corrupted volume tables to parse `$MFT`, `$STANDARD_INFORMATION`, `$FILE_NAME`, and non-resident `$DATA` cluster runlists, instantly recovering active, deleted, and orphaned files with original paths.
- 🎬 **High-Throughput Signature Carver (`carve`)**: Multi-threaded linear scanner (150+ MB/s) supporting movies (`MKV`, `MP4`, `AVI`), archives (`ZIP`, `DOCX`, `XLSX`, `PPTX`), documents (`PDF`), images (`JPEG`, `PNG`, `GIF`), and more.
- 🔄 **Smart Resume & Zero-Duplicate Validation**: Skips already-extracted files instantly upon re-running, eliminating redundant disk I/O and saving hours.
- 🛡️ **Bad-Sector Tolerant Disk Imager (`image`)**: Multi-pass imaging engine with byte-level mapfile tracking (`.map`), granular cluster retries, and direct hardware unbuffered I/O (`FILE_FLAG_NO_BUFFERING`).
- 🧭 **Heuristic Partition Scanner (`partitions`)**: Scans unpartitioned or wiped drives for orphaned VBR/PBR boot sectors across sector boundaries in milliseconds.

---

## 🏗️ Architecture

Recoverar is organized as a modular, high-performance Rust workspace:

```text
recoverar/
├── Cargo.toml                      # Workspace root manifest
├── crates/
│   ├── recovery_core/              # Core abstractions, BinaryReader, Error types
│   ├── disk_io/                    # Direct Win32 block I/O, sector buffers, disk imager, mapfile engine
│   ├── partition_analyzer/         # MBR, GPT, EBR chain parser, and heuristic boot sector scanner
│   ├── ntfs_engine/                # VBR, MFT record decoder, cluster runlists, and folder tree reconstructor
│   ├── carver/                     # Parallel Rayon signature scanner, format validators (MKV, MP4, JPEG, ZIP, etc.)
│   └── recovery_cli/               # Recoverar command-line interface & automated demo testbench
```

---

## 🚀 Prerequisites & Setup

### Prerequisites
1. **Rust & Cargo** (1.75+ recommended): [https://rustup.rs/](https://rustup.rs/)
2. **Visual Studio C++ Build Tools** (MSVC on Windows)

### Build from Source

Clone the repository and compile the optimized release binary:

```powershell
# 1. Clone repository
git clone https://github.com/nmkyuppie/recoverar.git
cd recoverar

# 2. Build optimized release binary
cargo build --release --bin recoverar

# 3. The compiled binary will be located at:
# .\target\release\recoverar.exe
```

---

## 📖 Usage Guide & Commands

> [!NOTE]
> When accessing raw physical drives (e.g. `\\.\PhysicalDrive2`) on Windows, open your PowerShell or Command Prompt as **Administrator**.

### 1. 1-Click Full Disk Automated Recovery (`auto-recover`)
Scans all primary and extended partitions on the drive, resolves NTFS directory trees, extracts files with their original folder structure, and automatically falls back to raw carving if a partition has severe filesystem damage:

```powershell
.\recoverar.exe auto-recover --device "\\.\PhysicalDrive2" --out-dir "D:\recovered_harddisk"
```

### 2. Direct NTFS File Tree Extraction (`ntfs`)
Directly target an NTFS partition by its byte offset or start LBA to restore the original folder hierarchy:

```powershell
# Extract all files from an NTFS volume at offset 838067311616 (~780 GB)
.\recoverar.exe ntfs --device "\\.\PhysicalDrive2" --offset 838067311616 --max-records 50000 --out-dir "D:\recovered_partition_4"
```

### 3. High-Speed Raw Signature Carving (`carve`)
Carve unallocated space or formatted partitions for photos, videos, movies, and documents:

```powershell
# Carve 300 GB starting at offset 140135126016
.\recoverar.exe carve --device "\\.\PhysicalDrive2" --start-offset 140135126016 --length 322122547200 --out-dir "D:\carved_media"
```

### 4. Partition Table Discovery & Heuristic Scanner (`partitions`)
Inspect partition tables and discover hidden or lost partitions:

```powershell
# Analyze MBR / GPT partition layout
.\recoverar.exe partitions --device "\\.\PhysicalDrive2"

# Deep heuristic scan for lost volume boot sectors
.\recoverar.exe partitions --device "\\.\PhysicalDrive2" --scan-orphaned
```

### 5. Multi-Pass Disk Imager with Mapfile (`image`)
Safely clone a failing hard drive to an image file with bad sector skipping and resume support:

```powershell
# Clone raw drive to disk image
.\recoverar.exe image --source "\\.\PhysicalDrive2" --dest "E:\disk_backup.raw" --mapfile "E:\disk_backup.map" --chunk-kb 64
```

### 6. End-to-End Test & Verification Demo (`demo`)
Creates an in-memory synthetic damaged disk with partitioned structures, damaged records, and embedded media, then runs automated end-to-end recovery tests:

```powershell
.\recoverar.exe demo --output "test_disk.img"
```

---

## 📊 Real-World Verification

Tested and validated on corrupted 1TB multi-partition mechanical storage drives:
- **87,000+ files (~370 GB)** extracted with original UTF-8 / Unicode filenames and full folder paths.
- Rescued complete software projects, Eclipse workspaces, SVN repositories, Tomcat configurations, and Java/JSP applications.
- Carved 1080p/4K MKV movies, MP4 clips, AVI videos, ZIP archives, Office documents, and JPEGs.

---

## 📄 License
This project is licensed under the MIT License.
