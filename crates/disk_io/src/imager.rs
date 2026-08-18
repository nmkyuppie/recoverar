use crate::aligned_buffer::AlignedBuffer;
use crate::block_reader::BlockDevice;
use crate::mapfile::{BlockStatus, RecoveryMapFile};
use crate::stats::RecoveryStats;
use recovery_core::error::Result;
use std::path::Path;

pub struct ImagerConfig {
    pub chunk_size: usize,
    pub sector_size: u32,
    pub sync_mapfile_every_mb: u64,
}

impl Default for ImagerConfig {
    fn default() -> Self {
        Self {
            chunk_size: 64 * 1024, // 64 KB default chunk read
            sector_size: 512,
            sync_mapfile_every_mb: 10,
        }
    }
}

pub struct DiskImager<'a> {
    source: &'a mut dyn BlockDevice,
    dest: &'a mut dyn BlockDevice,
    config: ImagerConfig,
    mapfile: RecoveryMapFile,
    stats: RecoveryStats,
}

impl<'a> DiskImager<'a> {
    pub fn new(
        source: &'a mut dyn BlockDevice,
        dest: &'a mut dyn BlockDevice,
        config: ImagerConfig,
        mapfile: Option<RecoveryMapFile>,
    ) -> Self {
        let total_size = source.total_size();
        let total_sectors = total_size / config.sector_size as u64;
        let mapfile = mapfile.unwrap_or_else(|| RecoveryMapFile::new_initial(total_size));
        let stats = RecoveryStats::new(total_sectors, config.sector_size);

        Self {
            source,
            dest,
            config,
            mapfile,
            stats,
        }
    }

    pub fn stats(&self) -> &RecoveryStats {
        &self.stats
    }

    pub fn mapfile(&self) -> &RecoveryMapFile {
        &self.mapfile
    }

    /// Execute the disk imaging loop with bad sector recovery and adaptive fallback.
    pub fn run_imaging<F, P>(&mut self, mapfile_path: Option<P>, mut progress_callback: F) -> Result<()>
    where
        F: FnMut(&RecoveryStats),
        P: AsRef<Path>,
    {
        let total_size = self.source.total_size();
        let chunk_size = self.config.chunk_size;
        let sector_size = self.config.sector_size as usize;

        let mut chunk_buf = AlignedBuffer::with_alignment(chunk_size, 4096);
        let mut sector_buf = AlignedBuffer::with_alignment(sector_size, 4096);
        let zero_sector = vec![0u8; sector_size];

        let mut last_map_sync = 0u64;

        // Iterate over non-tried blocks from mapfile
        let blocks_to_process: Vec<(u64, u64)> = self
            .mapfile
            .blocks
            .iter()
            .filter(|b| b.status == BlockStatus::NonTried)
            .map(|b| (b.pos, b.size))
            .collect();

        for (block_start, block_len) in blocks_to_process {
            let mut offset = block_start;
            let block_end = (block_start + block_len).min(total_size);

            while offset < block_end {
                let this_chunk = ((block_end - offset) as usize).min(chunk_size);
                let chunk_slice = &mut chunk_buf.as_mut_slice()[..this_chunk];

                // Attempt fast chunk read
                match self.source.read_exact_at(offset, chunk_slice) {
                    Ok(()) => {
                        // Chunk read succeeded -> write directly to destination
                        self.dest.write_exact_at(offset, chunk_slice)?;
                        let sectors_read = (this_chunk / sector_size) as u64;
                        self.stats.record_good_sectors(sectors_read);
                        self.mapfile.update_range(offset, this_chunk as u64, BlockStatus::Finished);
                        offset += this_chunk as u64;
                    }
                    Err(_) => {
                        // Chunk read failed -> drop down to sector-by-sector fallback
                        let mut sector_offset = offset;
                        let chunk_end = offset + this_chunk as u64;

                        while sector_offset < chunk_end {
                            let this_sector_len = ((chunk_end - sector_offset) as usize).min(sector_size);
                            let sec_slice = &mut sector_buf.as_mut_slice()[..this_sector_len];

                            match self.source.read_exact_at(sector_offset, sec_slice) {
                                Ok(()) => {
                                    self.dest.write_exact_at(sector_offset, sec_slice)?;
                                    self.stats.record_good_sectors(1);
                                    self.mapfile.update_range(
                                        sector_offset,
                                        this_sector_len as u64,
                                        BlockStatus::Finished,
                                    );
                                }
                                Err(_) => {
                                    // Bad sector -> zero-pad destination and record bad block
                                    self.dest.write_exact_at(sector_offset, &zero_sector[..this_sector_len])?;
                                    self.stats.record_bad_sectors(1);
                                    self.mapfile.update_range(
                                        sector_offset,
                                        this_sector_len as u64,
                                        BlockStatus::BadSector,
                                    );
                                }
                            }

                            sector_offset += this_sector_len as u64;
                        }

                        offset = chunk_end;
                    }
                }

                // Fire progress callback
                progress_callback(&self.stats);

                // Periodic mapfile flush
                let rescued_mb = self.stats.rescued_bytes() / (1024 * 1024);
                if rescued_mb.saturating_sub(last_map_sync) >= self.config.sync_mapfile_every_mb {
                    if let Some(ref path) = mapfile_path {
                        let _ = self.mapfile.save_to_file(path);
                    }
                    last_map_sync = rescued_mb;
                }
            }
        }

        // Final mapfile flush
        if let Some(ref path) = mapfile_path {
            let _ = self.mapfile.save_to_file(path);
        }

        Ok(())
    }
}
