//! Appendable heaps for the writer. Each builder keeps the bytes of the heap
//! that it starts from, so the indices of the existing entries stay valid,
//! and reuses an equal entry when one exists.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::bytes::put_compressed_u32;
use crate::error::{Error, Result};
use crate::heaps::{
    BlobHeap, BlobIndex, Guid, GuidHeap, GuidIndex, StringIndex, StringsHeap, UserStringsHeap,
};
use crate::token::Token;

fn offset_of(len: usize, structure: &'static str) -> Result<u32> {
    u32::try_from(len).map_err(|_| Error::Overflow {
        structure,
        value: len as u64,
    })
}

/// A `#Strings` heap that grows.
#[derive(Debug, Clone)]
pub struct StringsHeapBuilder {
    data: Vec<u8>,
    known: Option<BTreeMap<Vec<u8>, u32>>,
}

impl Default for StringsHeapBuilder {
    fn default() -> Self {
        Self {
            data: alloc::vec![0],
            known: None,
        }
    }
}

impl StringsHeapBuilder {
    /// Starts from the bytes of an existing heap.
    #[must_use]
    pub fn from_heap(heap: &StringsHeap<'_>) -> Self {
        if heap.data().is_empty() {
            return Self::default();
        }
        Self {
            data: heap.data().to_vec(),
            known: None,
        }
    }

    /// Adds a string and returns its index. The empty string is index 0.
    ///
    /// # Errors
    ///
    /// Returns an error when the string holds a zero byte or the heap
    /// passes 4 GiB.
    pub fn add(&mut self, value: &str) -> Result<StringIndex> {
        if value.is_empty() {
            return Ok(StringIndex(0));
        }
        if value.as_bytes().contains(&0) {
            return Err(Error::Malformed {
                structure: "#Strings",
                offset: self.data.len(),
                reason: "a string of the heap cannot hold a zero byte",
            });
        }
        let data = &self.data;
        let known = self.known.get_or_insert_with(|| {
            StringsHeap::new(data)
                .iter()
                .map(|(index, bytes)| (bytes.to_vec(), index.0))
                .collect()
        });
        if let Some(&index) = known.get(value.as_bytes()) {
            return Ok(StringIndex(index));
        }
        let index = offset_of(self.data.len(), "#Strings")?;
        self.data.extend_from_slice(value.as_bytes());
        self.data.push(0);
        known.insert(value.as_bytes().to_vec(), index);
        Ok(StringIndex(index))
    }

    /// Returns the bytes of the heap.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// A `#Blob` heap that grows.
#[derive(Debug, Clone)]
pub struct BlobHeapBuilder {
    data: Vec<u8>,
    known: Option<BTreeMap<Vec<u8>, u32>>,
}

impl Default for BlobHeapBuilder {
    fn default() -> Self {
        Self {
            data: alloc::vec![0],
            known: None,
        }
    }
}

impl BlobHeapBuilder {
    /// Starts from the bytes of an existing heap.
    #[must_use]
    pub fn from_heap(heap: &BlobHeap<'_>) -> Self {
        if heap.data().is_empty() {
            return Self::default();
        }
        Self {
            data: heap.data().to_vec(),
            known: None,
        }
    }

    /// Adds a blob and returns its index. The empty blob is index 0.
    ///
    /// # Errors
    ///
    /// Returns an error when the blob or the heap is too large.
    pub fn add(&mut self, value: &[u8]) -> Result<BlobIndex> {
        if value.is_empty() {
            return Ok(BlobIndex(0));
        }
        let data = &self.data;
        // Index 0 reads as the empty blob whatever the heap holds there.
        let known = self.known.get_or_insert_with(|| {
            BlobHeap::new(data)
                .iter()
                .filter(|(index, _)| index.0 != 0)
                .map(|(index, bytes)| (bytes.to_vec(), index.0))
                .collect()
        });
        if let Some(&index) = known.get(value) {
            return Ok(BlobIndex(index));
        }
        let index = offset_of(self.data.len(), "#Blob")?;
        put_compressed_u32(&mut self.data, offset_of(value.len(), "#Blob")?, "#Blob")?;
        self.data.extend_from_slice(value);
        known.insert(value.to_vec(), index);
        Ok(BlobIndex(index))
    }

    /// Returns the bytes of the heap.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// A `#US` heap that grows.
#[derive(Debug, Clone)]
pub struct UserStringsHeapBuilder {
    data: Vec<u8>,
}

impl Default for UserStringsHeapBuilder {
    fn default() -> Self {
        Self {
            data: alloc::vec![0],
        }
    }
}

impl UserStringsHeapBuilder {
    /// Starts from the bytes of an existing heap.
    #[must_use]
    pub fn from_heap(heap: &UserStringsHeap<'_>) -> Self {
        if heap.data().is_empty() {
            return Self::default();
        }
        Self {
            data: heap.data().to_vec(),
        }
    }

    /// Adds a string and returns its `ldstr` token.
    ///
    /// # Errors
    ///
    /// Returns an error when the heap passes the 24-bit offset of a token.
    pub fn add(&mut self, value: &str) -> Result<Token> {
        let offset = offset_of(self.data.len(), "#US")?;
        if offset > 0x00FF_FFFF {
            return Err(Error::Overflow {
                structure: "#US",
                value: u64::from(offset),
            });
        }
        let units: Vec<u16> = value.encode_utf16().collect();
        let len = offset_of(units.len() * 2 + 1, "#US")?;
        put_compressed_u32(&mut self.data, len, "#US")?;
        let mut flag = 0;
        for unit in units {
            self.data.extend_from_slice(&unit.to_le_bytes());
            if needs_flag(unit) {
                flag = 1;
            }
        }
        self.data.push(flag);
        Ok(Token::user_string(offset))
    }

    /// Returns the bytes of the heap.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Returns `true` for a code unit that sets the final byte (II.24.2.4).
const fn needs_flag(unit: u16) -> bool {
    unit > 0xFF || matches!(unit, 0x01..=0x08 | 0x0E..=0x1F | 0x27 | 0x2D | 0x7F)
}

/// A `#GUID` heap that grows.
#[derive(Debug, Clone, Default)]
pub struct GuidHeapBuilder {
    data: Vec<u8>,
    /// The bytes after a heap whose size is not a multiple of 16, which its
    /// last GUID ends in.
    tail: Vec<u8>,
}

impl GuidHeapBuilder {
    /// Starts from the bytes of an existing heap. A heap whose size is not a
    /// multiple of 16 keeps the bytes after it that its last GUID ends in
    /// (see [`GuidHeap::with_bytes_after`]); the writer writes them after
    /// the heap, outside the size of the stream.
    #[must_use]
    pub fn from_heap(heap: &GuidHeap<'_>) -> Self {
        Self {
            data: heap.data().to_vec(),
            tail: heap.tail().to_vec(),
        }
    }

    /// Adds a GUID and returns its 1-based index. An equal GUID is reused. A
    /// heap whose size is not a multiple of 16 first gets the bytes after it
    /// that its last GUID ends in, then zero bytes, so the new GUID starts at
    /// a GUID boundary and the last GUID keeps its value.
    ///
    /// # Errors
    ///
    /// Returns an error when the heap passes 4 GiB.
    pub fn add(&mut self, value: Guid) -> Result<GuidIndex> {
        let (guids, _) = self.data.as_chunks::<16>();
        if let Some(position) = guids.iter().position(|guid| *guid == value.0) {
            return Ok(GuidIndex(offset_of(position + 1, "#GUID")?));
        }
        self.data.append(&mut self.tail);
        self.data.resize(self.data.len().next_multiple_of(16), 0);
        self.data.extend_from_slice(&value.0);
        Ok(GuidIndex(offset_of(self.data.len() / 16, "#GUID")?))
    }

    /// Returns the bytes of the heap.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Returns the bytes after the heap that its last GUID ends in.
    pub(crate) fn tail(&self) -> &[u8] {
        &self.tail
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_builders_add_entries_that_the_views_read_back() {
        let mut strings = StringsHeapBuilder::from_heap(&StringsHeap::new(b"\0Hello\0"));
        assert_eq!(strings.add("Hello").unwrap(), StringIndex(1));
        let world = strings.add("World").unwrap();
        assert_eq!(world, StringIndex(7));
        assert_eq!(
            StringsHeap::new(strings.as_bytes()).get(world).unwrap(),
            "World"
        );
        assert!(strings.add("a\0b").is_err());

        let mut blobs = BlobHeapBuilder::default();
        let blob = blobs.add(&[1, 2, 3]).unwrap();
        assert_eq!(blobs.add(&[1, 2, 3]).unwrap(), blob);
        assert_eq!(
            BlobHeap::new(blobs.as_bytes()).get(blob).unwrap(),
            &[1, 2, 3]
        );

        let mut user = UserStringsHeapBuilder::default();
        let token = user.add("don't").unwrap();
        let read = UserStringsHeap::new(user.as_bytes())
            .get_token(token)
            .unwrap();
        assert_eq!(read.to_string().unwrap(), "don't");
        assert_eq!(read.flag(), 1);

        let mut guids = GuidHeapBuilder::default();
        let first = guids.add(Guid([1; 16])).unwrap();
        assert_eq!(first, GuidIndex(1));
        assert_eq!(guids.add(Guid([2; 16])).unwrap(), GuidIndex(2));
        assert_eq!(guids.add(Guid([1; 16])).unwrap(), first);

        let mut partial = GuidHeapBuilder::from_heap(&GuidHeap::new(&[7; 8]));
        assert_eq!(partial.add(Guid([3; 16])).unwrap(), GuidIndex(2));
        let heap = GuidHeap::new(partial.as_bytes());
        assert_eq!(heap.get(GuidIndex(2)).unwrap(), Some(Guid([3; 16])));

        // A heap of 8 bytes keeps the 8 bytes after it that its GUID ends
        // in, and adding a GUID completes the first one with them.
        let bytes: [u8; 16] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let short = GuidHeap::with_bytes_after(&bytes[..8], &bytes[8..]);
        let mut builder = GuidHeapBuilder::from_heap(&short);
        assert_eq!(builder.tail(), &bytes[8..]);
        assert_eq!(builder.add(Guid([3; 16])).unwrap(), GuidIndex(2));
        assert_eq!(builder.tail(), &[] as &[u8]);
        let heap = GuidHeap::new(builder.as_bytes());
        assert_eq!(heap.get(GuidIndex(1)).unwrap(), Some(Guid(bytes)));
    }
}
