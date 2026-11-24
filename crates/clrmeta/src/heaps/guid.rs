//! The `#GUID` heap (II.24.2.5): 16-byte GUIDs with 1-based indices.

use core::fmt;

use crate::error::{Error, HeapKind, Result};
use crate::heaps::GuidIndex;

/// A GUID in the byte order of the heap (the layout of the Windows `GUID`
/// structure in little-endian memory).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Guid(pub [u8; 16]);

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Guid({self})")
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-",
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            u16::from_le_bytes([b[4], b[5]]),
            u16::from_le_bytes([b[6], b[7]])
        )?;
        write!(f, "{:02x}{:02x}-", b[8], b[9])?;
        b[10..].iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

/// The `#GUID` heap over borrowed bytes.
#[derive(Debug, Clone, Copy, Default)]
pub struct GuidHeap<'a> {
    data: &'a [u8],
}

impl<'a> GuidHeap<'a> {
    /// Makes a view of the bytes of the heap.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Returns the bytes of the heap.
    #[must_use]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Returns the number of GUIDs.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len() / 16
    }

    /// Returns `true` when the heap holds no GUID.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the GUID at a 1-based index, or `None` for index 0.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HeapIndex`] when the index is outside the heap.
    pub fn get(&self, index: GuidIndex) -> Result<Option<Guid>> {
        if index.0 == 0 {
            return Ok(None);
        }
        let start = (index.0 as usize - 1) * 16;
        let bytes = self.data.get(start..start + 16).ok_or(Error::HeapIndex {
            heap: HeapKind::Guid,
            index: index.0,
        })?;
        let mut guid = [0; 16];
        guid.copy_from_slice(bytes);
        Ok(Some(Guid(guid)))
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn a_guid_is_read_by_its_one_based_index_and_shows_in_registry_form() {
        let mut data = [0u8; 32];
        data[16..].copy_from_slice(&[
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ]);
        let heap = GuidHeap::new(&data);
        assert_eq!(heap.len(), 2);
        assert_eq!(heap.get(GuidIndex(0)).unwrap(), None);
        let guid = heap.get(GuidIndex(2)).unwrap().unwrap();
        assert_eq!(guid.to_string(), "00112233-4455-6677-8899-aabbccddeeff");
        assert!(heap.get(GuidIndex(3)).is_err());
    }
}
