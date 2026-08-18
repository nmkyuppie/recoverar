pub mod aligned_buffer;
pub mod block_reader;
pub mod mapfile;
pub mod stats;
pub mod imager;

pub use aligned_buffer::AlignedBuffer;
pub use block_reader::{BlockDevice, FileBlockDevice, open_block_device};
#[cfg(windows)]
pub use block_reader::Win32DirectBlockDevice;
pub use mapfile::{BlockStatus, MapBlock, RecoveryMapFile};
pub use stats::RecoveryStats;
pub use imager::{DiskImager, ImagerConfig};

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_aligned_buffer() {
        let mut buf = AlignedBuffer::with_alignment(1024, 4096);
        assert_eq!(buf.len(), 1024);
        buf.as_mut_slice()[0] = 0xAA;
        assert_eq!(buf[0], 0xAA);
        buf.fill_zero();
        assert_eq!(buf[0], 0x00);
    }

    #[test]
    fn test_mapfile_update_and_save() {
        let temp = NamedTempFile::new().unwrap();
        let mut map = RecoveryMapFile::new_initial(1024 * 1024);
        assert_eq!(map.blocks.len(), 1);

        // Mark 0..4096 as finished
        map.update_range(0, 4096, BlockStatus::Finished);
        assert_eq!(map.blocks.len(), 2);
        assert_eq!(map.blocks[0].status, BlockStatus::Finished);
        assert_eq!(map.blocks[1].status, BlockStatus::NonTried);

        // Mark 4096..8192 as bad sector
        map.update_range(4096, 4096, BlockStatus::BadSector);
        assert_eq!(map.blocks.len(), 3);

        map.save_to_file(temp.path()).unwrap();
        let loaded = RecoveryMapFile::load_from_file(temp.path()).unwrap();
        assert_eq!(loaded.blocks.len(), 3);
    }

    #[test]
    fn test_imager_with_file_blocks() {
        let src_file = NamedTempFile::new().unwrap();
        let dst_file = NamedTempFile::new().unwrap();

        let data = vec![0x42u8; 128 * 1024];
        std::fs::write(src_file.path(), &data).unwrap();

        let mut src_dev = FileBlockDevice::open(src_file.path(), true, 512).unwrap();
        let mut dst_dev = FileBlockDevice::create_new(dst_file.path(), 128 * 1024, 512).unwrap();

        let config = ImagerConfig {
            chunk_size: 16 * 1024,
            sector_size: 512,
            sync_mapfile_every_mb: 1,
        };

        let mut imager = DiskImager::new(&mut src_dev, &mut dst_dev, config, None);
        imager.run_imaging::<_, &str>(None, |_| {}).unwrap();

        assert_eq!(imager.stats().rescued_bytes(), 128 * 1024);
        assert_eq!(imager.stats().bad_bytes(), 0);

        let copied = std::fs::read(dst_file.path()).unwrap();
        assert_eq!(copied, data);
    }
}
