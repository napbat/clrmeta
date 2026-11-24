//! The heaps of the metadata (ECMA-335 II.24.2.2 to II.24.2.5): borrowed
//! views for the reader and appendable builders for the writer.

mod blob;
mod builder;
mod guid;
mod strings;
mod user_strings;

pub use blob::{BlobHeap, BlobIter};
pub use builder::{BlobHeapBuilder, GuidHeapBuilder, StringsHeapBuilder, UserStringsHeapBuilder};
pub use guid::{Guid, GuidHeap};
pub use strings::{StringsHeap, StringsIter};
pub use user_strings::{UserString, UserStringsHeap, UserStringsIter};

/// An offset into the `#Strings` heap. Offset 0 is the empty string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct StringIndex(pub u32);

/// A 1-based index into the `#GUID` heap. Index 0 is the null GUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct GuidIndex(pub u32);

/// An offset into the `#Blob` heap. Offset 0 is the empty blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct BlobIndex(pub u32);
