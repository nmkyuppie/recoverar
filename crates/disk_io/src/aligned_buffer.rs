use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::ops::{Deref, DerefMut};

/// Memory buffer aligned to a power-of-two boundary (typically 4096 bytes for direct disk I/O).
pub struct AlignedBuffer {
    ptr: *mut u8,
    layout: Layout,
    len: usize,
}

// Safety: The buffer owns its allocated memory exclusively and is safe to transfer between threads.
unsafe impl Send for AlignedBuffer {}
unsafe impl Sync for AlignedBuffer {}

impl AlignedBuffer {
    pub const DEFAULT_ALIGNMENT: usize = 4096;

    pub fn new(size: usize) -> Self {
        Self::with_alignment(size, Self::DEFAULT_ALIGNMENT)
    }

    pub fn with_alignment(size: usize, align: usize) -> Self {
        assert!(align.is_power_of_two(), "Alignment must be a power of two");
        let effective_size = (size + align - 1) & !(align - 1);
        let layout = Layout::from_size_align(effective_size, align)
            .expect("Invalid layout for aligned buffer");

        let ptr = unsafe { alloc_zeroed(layout) };
        if ptr.is_null() {
            std::alloc::handle_alloc_error(layout);
        }

        Self {
            ptr,
            layout,
            len: size,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn fill_zero(&mut self) {
        unsafe {
            std::ptr::write_bytes(self.ptr, 0, self.len);
        }
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                dealloc(self.ptr, self.layout);
            }
        }
    }
}

impl Deref for AlignedBuffer {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl DerefMut for AlignedBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}
