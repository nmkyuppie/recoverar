use crate::error::{RecoveryError, Result};
use crate::types::Guid;

/// Safe bounds-checked binary reader over a byte slice.
pub struct BinaryReader<'a> {
    data: &'a [u8],
    cursor: usize,
}

impl<'a> BinaryReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, cursor: 0 }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn position(&self) -> usize {
        self.cursor
    }

    pub fn remaining(&self) -> usize {
        if self.cursor <= self.data.len() {
            self.data.len() - self.cursor
        } else {
            0
        }
    }

    pub fn seek(&mut self, pos: usize) -> Result<()> {
        if pos > self.data.len() {
            return Err(RecoveryError::BufferOutOfBounds {
                offset: pos,
                required: 0,
                available: self.data.len(),
            });
        }
        self.cursor = pos;
        Ok(())
    }

    pub fn skip(&mut self, count: usize) -> Result<()> {
        self.seek(self.cursor + count)
    }

    pub fn read_bytes(&mut self, count: usize) -> Result<&'a [u8]> {
        if self.cursor + count > self.data.len() {
            return Err(RecoveryError::BufferOutOfBounds {
                offset: self.cursor,
                required: count,
                available: self.data.len().saturating_sub(self.cursor),
            });
        }
        let slice = &self.data[self.cursor..self.cursor + count];
        self.cursor += count;
        Ok(slice)
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        let bytes = self.read_bytes(1)?;
        Ok(bytes[0])
    }

    pub fn read_u16_le(&mut self) -> Result<u16> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub fn read_u32_le(&mut self) -> Result<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub fn read_u64_le(&mut self) -> Result<u64> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub fn read_i64_le(&mut self) -> Result<i64> {
        let bytes = self.read_bytes(8)?;
        Ok(i64::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub fn read_u16_be(&mut self) -> Result<u16> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_be_bytes(bytes.try_into().unwrap()))
    }

    pub fn read_u32_be(&mut self) -> Result<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
    }

    pub fn read_u64_be(&mut self) -> Result<u64> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
    }

    pub fn read_guid_le(&mut self) -> Result<Guid> {
        let bytes = self.read_bytes(16)?;
        Guid::from_bytes_le(bytes).ok_or_else(|| RecoveryError::BufferOutOfBounds {
            offset: self.cursor - 16,
            required: 16,
            available: 0,
        })
    }

    pub fn read_utf16_le_string(&mut self, char_count: usize) -> Result<String> {
        let byte_count = char_count * 2;
        let bytes = self.read_bytes(byte_count)?;
        let u16_chars: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        Ok(String::from_utf16_lossy(&u16_chars))
    }

    pub fn read_ascii_string(&mut self, length: usize) -> Result<String> {
        let bytes = self.read_bytes(length)?;
        Ok(String::from_utf8_lossy(bytes).trim_end_matches('\0').to_string())
    }

    /// Read bytes at absolute offset without modifying internal cursor
    pub fn peek_bytes_at(data: &[u8], offset: usize, count: usize) -> Result<&[u8]> {
        if offset + count > data.len() {
            return Err(RecoveryError::BufferOutOfBounds {
                offset,
                required: count,
                available: data.len().saturating_sub(offset),
            });
        }
        Ok(&data[offset..offset + count])
    }

    pub fn peek_u16_le_at(data: &[u8], offset: usize) -> Result<u16> {
        let slice = Self::peek_bytes_at(data, offset, 2)?;
        Ok(u16::from_le_bytes(slice.try_into().unwrap()))
    }

    pub fn peek_u32_le_at(data: &[u8], offset: usize) -> Result<u32> {
        let slice = Self::peek_bytes_at(data, offset, 4)?;
        Ok(u32::from_le_bytes(slice.try_into().unwrap()))
    }

    pub fn peek_u64_le_at(data: &[u8], offset: usize) -> Result<u64> {
        let slice = Self::peek_bytes_at(data, offset, 8)?;
        Ok(u64::from_le_bytes(slice.try_into().unwrap()))
    }

    pub fn peek_u16_be_at(data: &[u8], offset: usize) -> Result<u16> {
        let slice = Self::peek_bytes_at(data, offset, 2)?;
        Ok(u16::from_be_bytes(slice.try_into().unwrap()))
    }

    pub fn peek_u32_be_at(data: &[u8], offset: usize) -> Result<u32> {
        let slice = Self::peek_bytes_at(data, offset, 4)?;
        Ok(u32::from_be_bytes(slice.try_into().unwrap()))
    }

    pub fn peek_u64_be_at(data: &[u8], offset: usize) -> Result<u64> {
        let slice = Self::peek_bytes_at(data, offset, 8)?;
        Ok(u64::from_be_bytes(slice.try_into().unwrap()))
    }
}
