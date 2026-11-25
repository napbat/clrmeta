//! The writer of metadata: owned rows and heaps to the bytes of a metadata
//! root with its streams.

use alloc::borrow::Cow;
use alloc::vec::Vec;

use crate::bytes::{pad4, put_index};
use crate::error::{Error, Result};
use crate::heaps::{BlobHeapBuilder, GuidHeapBuilder, StringsHeapBuilder, UserStringsHeapBuilder};
use crate::metadata::Metadata;
use crate::pdb::PdbStream;
use crate::root::{MetadataRoot, StreamHeader, StreamSelection};
use crate::tables::{
    HEAP_BLOB_WIDE, HEAP_GUID_WIDE, HEAP_STRINGS_WIDE, Layout, TableId, TableRows, TablesHeader,
    columns, placed_counts,
};

/// The `sorted` mask that the reference compilers write: every table that
/// ECMA-335 requires to be sorted.
pub const DEFAULT_SORTED: u64 = 0x0000_1600_3301_FA00;

/// A stream of the output, in the order of the stream headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamSlot {
    /// The tables stream.
    Tables,
    /// The `#Strings` heap.
    Strings,
    /// The `#US` heap.
    UserStrings,
    /// The `#GUID` heap.
    Guid,
    /// The `#Blob` heap.
    Blob,
    /// The `#Pdb` stream.
    Pdb,
    /// A stream that the builder keeps as bytes: its name and its data.
    /// [`MetadataBuilder::from_metadata`] keeps each stream that the reader
    /// does not take this way, the extra heaps of an obfuscator included.
    Raw(Vec<u8>, Vec<u8>),
}

/// Owned metadata that writes to bytes.
///
/// [`MetadataBuilder::from_metadata`] copies parsed metadata: the rows of
/// every table, the heaps byte for byte (so every index stays valid), the
/// header fields and the order of the streams. The builders of the heaps
/// add entries, and [`MetadataBuilder::rows`] holds the rows.
#[derive(Debug, Clone)]
pub struct MetadataBuilder {
    /// The major version of the root (1).
    pub major_version: u16,
    /// The minor version of the root (1).
    pub minor_version: u16,
    /// The reserved field of the root.
    pub reserved: u32,
    /// The version field of the root: the version string of the runtime, a
    /// zero byte and padding. The writer writes the bytes as they are.
    pub version: Vec<u8>,
    /// The flags of the root.
    pub flags: u16,
    /// The template of the tables header: its reserved fields, versions,
    /// `sorted` mask, extra data, and the `heap_sizes` bits other than the
    /// index widths. The writer computes the row counts and the widths; a
    /// width bit of the template stays set.
    pub tables_header: TablesHeader,
    /// `true` writes the tables as `#-` (unoptimized), `false` as `#~`.
    pub uncompressed: bool,
    /// The bytes after the last row of the tables stream, before the
    /// padding to 4 bytes. Some compilers write a zero byte there.
    /// [`MetadataBuilder::from_metadata`] copies them.
    pub tables_trailer: Vec<u8>,
    /// The rows of every table.
    pub rows: TableRows,
    /// The `#Strings` heap.
    pub strings: StringsHeapBuilder,
    /// The `#US` heap.
    pub user_strings: UserStringsHeapBuilder,
    /// The `#GUID` heap.
    pub guids: GuidHeapBuilder,
    /// The `#Blob` heap.
    pub blobs: BlobHeapBuilder,
    /// The `#Pdb` stream of a portable PDB.
    pub pdb: Option<PdbStream>,
    /// The streams in output order. A heap that is not in the list is not
    /// written.
    pub streams: Vec<StreamSlot>,
}

impl MetadataBuilder {
    /// Makes empty metadata with a runtime version string. The version
    /// field gets a zero byte and padding to a multiple of 4.
    #[must_use]
    pub fn new(version: &str) -> Self {
        let mut field = version.as_bytes().to_vec();
        field.resize((field.len() + 1).next_multiple_of(4), 0);
        Self {
            major_version: 1,
            minor_version: 1,
            reserved: 0,
            version: field,
            flags: 0,
            tables_header: TablesHeader {
                sorted: DEFAULT_SORTED,
                ..TablesHeader::default()
            },
            uncompressed: false,
            tables_trailer: Vec::new(),
            rows: TableRows::default(),
            strings: StringsHeapBuilder::default(),
            user_strings: UserStringsHeapBuilder::default(),
            guids: GuidHeapBuilder::default(),
            blobs: BlobHeapBuilder::default(),
            pdb: None,
            streams: alloc::vec![
                StreamSlot::Tables,
                StreamSlot::Strings,
                StreamSlot::UserStrings,
                StreamSlot::Guid,
                StreamSlot::Blob,
            ],
        }
    }

    /// Copies parsed metadata.
    ///
    /// The streams that the reader takes (see
    /// [`StreamSelection`](crate::root::StreamSelection)) become the
    /// slots of the tables and the heaps. Every other stream stays a
    /// [`StreamSlot::Raw`] stream at its position. A slot writes the
    /// standard name, so a heap that the read-write reader takes by a name
    /// in another case (`#STRINGS`) gets the standard name.
    ///
    /// # Errors
    ///
    /// Returns an error when a row is not valid.
    pub fn from_metadata(metadata: &Metadata<'_>) -> Result<Self> {
        let root = metadata.root();
        let selection = metadata.stream_selection();
        let slots = [
            (selection.tables, StreamSlot::Tables),
            (selection.strings, StreamSlot::Strings),
            (selection.user_strings, StreamSlot::UserStrings),
            (selection.guids, StreamSlot::Guid),
            (selection.blobs, StreamSlot::Blob),
            (selection.pdb, StreamSlot::Pdb),
        ];
        let streams = (0..root.streams.len())
            .map(|index| {
                slots
                    .iter()
                    .find(|(selected, _)| *selected == Some(index))
                    .map_or_else(
                        || {
                            StreamSlot::Raw(
                                root.streams[index].name.to_vec(),
                                root.stream_data(metadata.data(), index).to_vec(),
                            )
                        },
                        |(_, slot)| slot.clone(),
                    )
            })
            .collect();
        Ok(Self {
            major_version: root.major_version,
            minor_version: root.minor_version,
            reserved: root.reserved,
            version: root.version.to_vec(),
            flags: root.flags,
            tables_header: metadata.tables().header().clone(),
            uncompressed: metadata.tables_stream_name().eq_ignore_ascii_case(b"#-"),
            tables_trailer: metadata
                .tables()
                .data()
                .get(metadata.tables().layout().end()..)
                .unwrap_or_default()
                .to_vec(),
            rows: metadata.tables().to_rows()?,
            strings: StringsHeapBuilder::from_heap(metadata.strings()),
            user_strings: UserStringsHeapBuilder::from_heap(metadata.user_strings()),
            guids: GuidHeapBuilder::from_heap(metadata.guids()),
            blobs: BlobHeapBuilder::from_heap(metadata.blobs()),
            pdb: metadata.pdb().cloned(),
            streams,
        })
    }

    /// Returns the slot of each stream in output order. Metadata without a
    /// `#US` stream, such as the output of an obfuscator that encrypted
    /// every string, gets one after `#Strings` (the order of ECMA-335
    /// II.24.2.2) when strings were added to the heap.
    fn slots(&self) -> Cow<'_, [StreamSlot]> {
        if self.user_strings.as_bytes().len() <= 1
            || self.streams.contains(&StreamSlot::UserStrings)
        {
            return Cow::Borrowed(&self.streams);
        }
        let mut slots = self.streams.clone();
        let at = slots
            .iter()
            .position(|slot| *slot == StreamSlot::Strings)
            .or_else(|| slots.iter().position(|slot| *slot == StreamSlot::Tables))
            .map_or(slots.len(), |at| at + 1);
        slots.insert(at, StreamSlot::UserStrings);
        Cow::Owned(slots)
    }

    /// Returns the name of each stream of `slots`.
    fn stream_names<'s>(&self, slots: &'s [StreamSlot]) -> impl Iterator<Item = &'s [u8]> {
        let tables_name: &[u8] = if self.uncompressed { b"#-" } else { b"#~" };
        slots.iter().map(move |slot| match slot {
            StreamSlot::Tables => tables_name,
            StreamSlot::Strings => b"#Strings",
            StreamSlot::UserStrings => b"#US",
            StreamSlot::Guid => b"#GUID",
            StreamSlot::Blob => b"#Blob",
            StreamSlot::Pdb => b"#Pdb",
            StreamSlot::Raw(name, _) => name.as_slice(),
        })
    }

    /// Writes the metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when a row holds a value that its column cannot
    /// hold, or a stream is larger than 4 GiB.
    pub fn write(&self) -> Result<Vec<u8>> {
        let slots = self.slots();
        let names: Vec<&[u8]> = self.stream_names(&slots).collect();
        let wide = StreamSelection::of(&names).jtd.is_some();
        let tables = self.write_tables(wide)?;
        let pdb = self.pdb.as_ref().map(PdbStream::write);
        // Each part: the name, the bytes of the stream, and the bytes after
        // it that its header does not count (the end of the last GUID of a
        // #GUID heap whose size is not a multiple of 16).
        let mut parts: Vec<(&[u8], &[u8], &[u8])> = Vec::with_capacity(slots.len());
        for (slot, &name) in slots.iter().zip(&names) {
            let (data, tail): (&[u8], &[u8]) = match slot {
                StreamSlot::Tables => (&tables, &[]),
                StreamSlot::Strings => (self.strings.as_bytes(), &[]),
                StreamSlot::UserStrings => (self.user_strings.as_bytes(), &[]),
                StreamSlot::Guid => (self.guids.as_bytes(), self.guids.tail()),
                StreamSlot::Blob => (self.blobs.as_bytes(), &[]),
                StreamSlot::Pdb => (pdb.as_deref().unwrap_or_default(), &[]),
                StreamSlot::Raw(_, data) => (data, &[]),
            };
            parts.push((name, data, tail));
        }
        let root = MetadataRoot {
            major_version: self.major_version,
            minor_version: self.minor_version,
            reserved: self.reserved,
            version: &self.version,
            flags: self.flags,
            streams: Vec::new(),
        };
        // A version field whose length is not a multiple of 4 leaves the
        // header unaligned; the streams still start at multiples of 4.
        let header_size =
            MetadataRoot::header_size(self.version.len(), parts.iter().map(|p| p.0.len()));
        let mut offset = header_size.next_multiple_of(4);
        let mut headers = Vec::with_capacity(parts.len());
        for &(name, data, tail) in &parts {
            // A stream with bytes after it keeps its exact size.
            let size = if tail.is_empty() {
                data.len().next_multiple_of(4)
            } else {
                data.len()
            };
            headers.push(StreamHeader {
                offset: to_u32(offset)?,
                size: to_u32(size)?,
                name,
            });
            offset += (data.len() + tail.len()).next_multiple_of(4);
        }
        let mut out = Vec::with_capacity(offset);
        MetadataRoot::write_header(&mut out, &root, &headers)?;
        for (_, data, tail) in parts {
            pad4(&mut out);
            out.extend_from_slice(data);
            out.extend_from_slice(tail);
        }
        pad4(&mut out);
        Ok(out)
    }

    /// Writes the tables stream. `wide` makes every index 4 bytes.
    ///
    /// Without a `#Pdb` stream, the reader places no rows for the debug
    /// tables, so the writer writes none and keeps the row counts of the
    /// template header for them, as it keeps the counts of the tables that
    /// the schema does not define.
    fn write_tables(&self, wide: bool) -> Result<Vec<u8>> {
        let mut header = self.tables_header.clone();
        let wide_heap = |len: usize, flag: u8| if len > 0xFFFF { flag } else { 0 };
        header.heap_sizes |= wide_heap(self.strings.as_bytes().len(), HEAP_STRINGS_WIDE)
            | wide_heap(self.guids.as_bytes().len() / 16, HEAP_GUID_WIDE)
            | wide_heap(self.blobs.as_bytes().len(), HEAP_BLOB_WIDE);
        let debug_tables = self.pdb.is_some();
        for &table in TableId::ALL {
            if !debug_tables && table as u8 >= TableId::Document as u8 {
                continue;
            }
            let count = to_u32(self.rows.row_count(table))?;
            let bit = 1u64 << table as u8;
            if count > 0 {
                header.valid |= bit;
            }
            header.row_counts[table as usize] = count;
        }
        let mut out = Vec::new();
        header.write(&mut out);
        let row_counts = placed_counts(&header.row_counts, debug_tables);
        let mut sizing = row_counts;
        if let Some(pdb) = &self.pdb {
            for (count, &external) in sizing.iter_mut().zip(&pdb.type_system_table_rows) {
                *count = (*count).max(external);
            }
        }
        let layout = Layout::compute(header.heap_sizes, &row_counts, &sizing, wide, out.len());
        for &table in TableId::ALL {
            let placed = layout.table(table);
            for position in 0..placed.row_count as usize {
                let row = self.rows.any_row(table, position).ok_or(Error::Overflow {
                    structure: "tables stream",
                    value: position as u64,
                })?;
                let row_number = to_u32(position + 1)?;
                let column_error = |column: usize, reason| Error::Column {
                    table,
                    row: row_number,
                    column: columns(table).get(column).map_or("?", |c| c.name),
                    reason,
                };
                let raw = row.to_raw().map_err(|column| {
                    column_error(column, "the coded index cannot name the table")
                })?;
                for (column, (&value, &width)) in raw.iter().zip(&placed.widths).enumerate() {
                    if width == 0 {
                        break;
                    }
                    put_index(&mut out, value, width, "tables stream")
                        .map_err(|_| column_error(column, "the value does not fit the column"))?;
                }
            }
        }
        out.extend_from_slice(&self.tables_trailer);
        pad4(&mut out);
        Ok(out)
    }
}

fn to_u32(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::Overflow {
        structure: "metadata",
        value: value as u64,
    })
}

mod rows;
#[cfg(test)]
mod tests;

pub use rows::{MethodRenumbering, RowReference};
