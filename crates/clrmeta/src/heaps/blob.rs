//! The `#Blob` heap (II.24.2.4): byte arrays with a compressed length.

use crate::bytes::Cursor;
use crate::error::{Error, HeapKind, Result};
use crate::heaps::BlobIndex;

/// The `#Blob` heap over borrowed bytes.
#[derive(Debug, Clone, Copy, Default)]
pub struct BlobHeap<'a> {
    data: &'a [u8],
}

impl<'a> BlobHeap<'a> {
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

    /// Returns the blob at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HeapIndex`] when the index or the blob is outside the
    /// heap. Index 0 of an empty heap is the empty blob.
    pub fn get(&self, index: BlobIndex) -> Result<&'a [u8]> {
        if index.0 == 0 && self.data.is_empty() {
            return Ok(&[]);
        }
        let error = Error::HeapIndex {
            heap: HeapKind::Blob,
            index: index.0,
        };
        let mut cursor =
            Cursor::at(self.data, index.0 as usize, "#Blob").map_err(|_| error.clone())?;
        let len = cursor.compressed_u32().map_err(|_| error.clone())?;
        cursor.bytes(len as usize).map_err(|_| error)
    }

    /// Iterates over the blobs in heap order. The iteration stops at the
    /// first length that is not valid (the padding of the stream).
    #[must_use]
    pub fn iter(&self) -> BlobIter<'a> {
        BlobIter {
            data: self.data,
            pos: 0,
        }
    }
}

impl<'a> IntoIterator for &BlobHeap<'a> {
    type Item = (BlobIndex, &'a [u8]);
    type IntoIter = BlobIter<'a>;

    fn into_iter(self) -> BlobIter<'a> {
        self.iter()
    }
}

/// The iterator over the blobs of a `#Blob` heap.
#[derive(Debug, Clone)]
pub struct BlobIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for BlobIter<'a> {
    type Item = (BlobIndex, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let mut cursor = Cursor::at(self.data, self.pos, "#Blob").ok()?;
        if cursor.is_empty() {
            return None;
        }
        let index = BlobIndex(u32::try_from(self.pos).ok()?);
        let len = cursor.compressed_u32().ok()?;
        let blob = cursor.bytes(len as usize).ok()?;
        self.pos = cursor.position();
        Some((index, blob))
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn a_blob_is_read_after_its_compressed_length() {
        let heap = BlobHeap::new(&[0x00, 0x03, 1, 2, 3, 0x80, 0x01, 9, 0x05]);
        assert_eq!(heap.get(BlobIndex(0)).unwrap(), &[] as &[u8]);
        assert_eq!(heap.get(BlobIndex(1)).unwrap(), &[1, 2, 3]);
        assert_eq!(heap.get(BlobIndex(5)).unwrap(), &[9]);
        assert!(heap.get(BlobIndex(8)).is_err());
        assert!(heap.get(BlobIndex(100)).is_err());
        let entries: Vec<_> = heap
            .iter()
            .map(|(index, blob)| (index.0, blob.len()))
            .collect();
        assert_eq!(entries, [(0, 0), (1, 3), (5, 1)]);
    }
}
