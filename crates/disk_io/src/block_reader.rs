use recovery_core::error::{RecoveryError, Result};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Trait representing a block-level storage medium (image file or physical drive).
pub trait BlockDevice: Send + Sync {
    fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()>;
    fn write_exact_at(&mut self, offset: u64, buf: &[u8]) -> Result<()>;
    fn total_size(&self) -> u64;
    fn sector_size(&self) -> u32;
}

/// Standard file-based block device for raw disk images (`.img`, `.raw`, `.dd`).
pub struct FileBlockDevice {
    file: File,
    size: u64,
    sector_size: u32,
    read_only: bool,
}

impl FileBlockDevice {
    pub fn open<P: AsRef<Path>>(path: P, read_only: bool, sector_size: u32) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(!read_only)
            .create(false)
            .open(path.as_ref())?;

        let size = file.metadata()?.len();
        Ok(Self {
            file,
            size,
            sector_size,
            read_only,
        })
    }

    pub fn create_new<P: AsRef<Path>>(path: P, size: u64, sector_size: u32) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path.as_ref())?;

        file.set_len(size)?;
        Ok(Self {
            file,
            size,
            sector_size,
            read_only: false,
        })
    }
}

impl BlockDevice for FileBlockDevice {
    fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(buf)?;
        Ok(())
    }

    fn write_exact_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        if self.read_only {
            return Err(RecoveryError::Other("Cannot write to read-only block device".into()));
        }
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(buf)?;
        Ok(())
    }

    fn total_size(&self) -> u64 {
        self.size
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }
}

#[cfg(windows)]
pub struct Win32DirectBlockDevice {
    handle: windows_sys::Win32::Foundation::HANDLE,
    size: u64,
    sector_size: u32,
    read_only: bool,
}

#[cfg(windows)]
impl Win32DirectBlockDevice {
    pub fn open(path: &str, read_only: bool, sector_size: u32) -> Result<Self> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::{INVALID_HANDLE_VALUE, GENERIC_READ, GENERIC_WRITE};
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING, FILE_FLAG_WRITE_THROUGH, GetFileSizeEx
        };

        let wide_path: Vec<u16> = OsStr::new(path).encode_wide().chain(std::iter::once(0)).collect();
        let access = if read_only {
            GENERIC_READ
        } else {
            GENERIC_READ | GENERIC_WRITE
        };

        let flags = FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH;

        let handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                flags,
                0,
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            return Err(RecoveryError::Io(std::io::Error::last_os_error()));
        }

        let size = Self::query_device_size(handle);

        Ok(Self {
            handle,
            size,
            sector_size,
            read_only,
        })
    }

    fn query_device_size(handle: windows_sys::Win32::Foundation::HANDLE) -> u64 {
        use windows_sys::Win32::Storage::FileSystem::GetFileSizeEx;
        use windows_sys::Win32::System::IO::DeviceIoControl;

        // 1. Try GetFileSizeEx for standard files
        let mut file_size: i64 = 0;
        if unsafe { GetFileSizeEx(handle, &mut file_size) } != 0 && file_size > 0 {
            return file_size as u64;
        }

        // 2. IOCTL_DISK_GET_LENGTH_INFO (0x0007405C) for physical drives and USB partitions
        const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007405C;
        let mut length_info: i64 = 0;
        let mut bytes_returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_DISK_GET_LENGTH_INFO,
                std::ptr::null(),
                0,
                &mut length_info as *mut i64 as _,
                std::mem::size_of::<i64>() as u32,
                &mut bytes_returned,
                std::ptr::null_mut(),
            )
        };
        if ok != 0 && length_info > 0 {
            return length_info as u64;
        }

        // 3. IOCTL_DISK_GET_DRIVE_GEOMETRY_EX (0x000700A0)
        const IOCTL_DISK_GET_DRIVE_GEOMETRY_EX: u32 = 0x000700A0;
        #[repr(C)]
        struct DiskGeometryExHeader {
            geometry: [u8; 24],
            disk_size: i64,
        }
        let mut geom = DiskGeometryExHeader {
            geometry: [0; 24],
            disk_size: 0,
        };
        let ok_geom = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                std::ptr::null(),
                0,
                &mut geom as *mut _ as _,
                std::mem::size_of::<DiskGeometryExHeader>() as u32,
                &mut bytes_returned,
                std::ptr::null_mut(),
            )
        };
        if ok_geom != 0 && geom.disk_size > 0 {
            return geom.disk_size as u64;
        }

        0
    }
}

#[cfg(windows)]
impl BlockDevice for Win32DirectBlockDevice {
    fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        use windows_sys::Win32::Storage::FileSystem::{SetFilePointerEx, ReadFile, FILE_BEGIN};

        let mut new_pos: i64 = 0;
        let seek_ok = unsafe {
            SetFilePointerEx(self.handle, offset as i64, &mut new_pos, FILE_BEGIN)
        };
        if seek_ok == 0 {
            return Err(RecoveryError::Io(std::io::Error::last_os_error()));
        }

        let mut bytes_read: u32 = 0;
        let read_ok = unsafe {
            ReadFile(
                self.handle,
                buf.as_mut_ptr() as _,
                buf.len() as u32,
                &mut bytes_read,
                std::ptr::null_mut(),
            )
        };

        if read_ok == 0 || bytes_read as usize != buf.len() {
            return Err(RecoveryError::Io(std::io::Error::last_os_error()));
        }

        Ok(())
    }

    fn write_exact_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        use windows_sys::Win32::Storage::FileSystem::{SetFilePointerEx, WriteFile, FILE_BEGIN};

        if self.read_only {
            return Err(RecoveryError::Other("Cannot write to read-only block device".into()));
        }

        let mut new_pos: i64 = 0;
        let seek_ok = unsafe {
            SetFilePointerEx(self.handle, offset as i64, &mut new_pos, FILE_BEGIN)
        };
        if seek_ok == 0 {
            return Err(RecoveryError::Io(std::io::Error::last_os_error()));
        }

        let mut bytes_written: u32 = 0;
        let write_ok = unsafe {
            WriteFile(
                self.handle,
                buf.as_ptr() as _,
                buf.len() as u32,
                &mut bytes_written,
                std::ptr::null_mut(),
            )
        };

        if write_ok == 0 || bytes_written as usize != buf.len() {
            return Err(RecoveryError::Io(std::io::Error::last_os_error()));
        }

        Ok(())
    }

    fn total_size(&self) -> u64 {
        self.size
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }
}

#[cfg(windows)]
impl Drop for Win32DirectBlockDevice {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

/// Helper function to open a block device automatically detecting physical device vs image file.
pub fn open_block_device(path: &str, read_only: bool, direct_io: bool, sector_size: u32) -> Result<Box<dyn BlockDevice>> {
    #[cfg(windows)]
    if direct_io || path.starts_with(r"\\.\") {
        if let Ok(direct_dev) = Win32DirectBlockDevice::open(path, read_only, sector_size) {
            return Ok(Box::new(direct_dev));
        }
    }

    let file_dev = FileBlockDevice::open(path, read_only, sector_size)?;
    Ok(Box::new(file_dev))
}
