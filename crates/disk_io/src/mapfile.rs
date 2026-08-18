use recovery_core::error::{RecoveryError, Result};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockStatus {
    NonTried,  // '?'
    Finished,  // '+'
    BadSector, // '-'
    NonTrimmed,// '/'
}

impl BlockStatus {
    pub fn to_char(self) -> char {
        match self {
            BlockStatus::NonTried => '?',
            BlockStatus::Finished => '+',
            BlockStatus::BadSector => '-',
            BlockStatus::NonTrimmed => '/',
        }
    }

    pub fn from_char(c: char) -> Option<Self> {
        match c {
            '?' => Some(BlockStatus::NonTried),
            '+' => Some(BlockStatus::Finished),
            '-' => Some(BlockStatus::BadSector),
            '/' => Some(BlockStatus::NonTrimmed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapBlock {
    pub pos: u64,
    pub size: u64,
    pub status: BlockStatus,
}

#[derive(Debug, Clone)]
pub struct RecoveryMapFile {
    pub current_pos: u64,
    pub current_status: BlockStatus,
    pub blocks: Vec<MapBlock>,
}

impl RecoveryMapFile {
    pub fn new_initial(total_size: u64) -> Self {
        Self {
            current_pos: 0,
            current_status: BlockStatus::NonTried,
            blocks: vec![MapBlock {
                pos: 0,
                size: total_size,
                status: BlockStatus::NonTried,
            }],
        }
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let mut current_pos = 0;
        let mut current_status = BlockStatus::NonTried;
        let mut blocks = Vec::new();

        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() == 2 {
                // Header line: current_pos current_status
                if let (Ok(pos), Some(status)) = (
                    Self::parse_hex_or_dec(parts[0]),
                    parts[1].chars().next().and_then(BlockStatus::from_char),
                ) {
                    current_pos = pos;
                    current_status = status;
                }
            } else if parts.len() == 3 {
                // Block line: pos size status
                if let (Ok(pos), Ok(size), Some(status)) = (
                    Self::parse_hex_or_dec(parts[0]),
                    Self::parse_hex_or_dec(parts[1]),
                    parts[2].chars().next().and_then(BlockStatus::from_char),
                ) {
                    blocks.push(MapBlock { pos, size, status });
                }
            }
        }

        if blocks.is_empty() {
            return Err(RecoveryError::Other("Invalid mapfile: no blocks found".into()));
        }

        Ok(Self {
            current_pos,
            current_status,
            blocks,
        })
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = File::create(path)?;
        writeln!(file, "# Antigravity Data Recovery Suite Mapfile")?;
        writeln!(file, "# Current_pos          Current_status")?;
        writeln!(
            file,
            "0x{:012X}     {}",
            self.current_pos,
            self.current_status.to_char()
        )?;
        writeln!(file, "#      pos                size        status")?;

        for block in &self.blocks {
            writeln!(
                file,
                "0x{:012X}     0x{:012X}     {}",
                block.pos,
                block.size,
                block.status.to_char()
            )?;
        }

        file.flush()?;
        Ok(())
    }

    /// Mark a byte range with a given status, merging contiguous blocks with same status.
    pub fn update_range(&mut self, offset: u64, length: u64, status: BlockStatus) {
        if length == 0 {
            return;
        }

        let range_end = offset + length;
        let mut new_blocks = Vec::with_capacity(self.blocks.len() + 2);

        for block in &self.blocks {
            let block_end = block.pos + block.size;

            if block_end <= offset || block.pos >= range_end {
                // No overlap
                new_blocks.push(block.clone());
            } else {
                // Overlaps with update range
                if block.pos < offset {
                    // Left piece
                    new_blocks.push(MapBlock {
                        pos: block.pos,
                        size: offset - block.pos,
                        status: block.status,
                    });
                }

                // Middle piece is inserted by our target range (done once below or merged)

                if block_end > range_end {
                    // Right piece
                    new_blocks.push(MapBlock {
                        pos: range_end,
                        size: block_end - range_end,
                        status: block.status,
                    });
                }
            }
        }

        // Insert new block
        new_blocks.push(MapBlock {
            pos: offset,
            size: length,
            status,
        });

        // Sort by position
        new_blocks.sort_by_key(|b| b.pos);

        // Compact contiguous blocks
        let mut compacted = Vec::with_capacity(new_blocks.len());
        for b in new_blocks {
            if let Some(last) = compacted.last_mut() {
                let last: &mut MapBlock = last;
                if last.pos + last.size == b.pos && last.status == b.status {
                    last.size += b.size;
                    continue;
                }
            }
            compacted.push(b);
        }

        self.blocks = compacted;
        self.current_pos = range_end;
        self.current_status = status;
    }

    fn parse_hex_or_dec(s: &str) -> std::result::Result<u64, ()> {
        if s.starts_with("0x") || s.starts_with("0X") {
            u64::from_str_radix(&s[2..], 16).map_err(|_| ())
        } else {
            s.parse::<u64>().map_err(|_| ())
        }
    }
}
