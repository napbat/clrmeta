//! The writer of metadata: owned rows and heaps to the bytes of a metadata
//! root with its streams.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::bytes::{pad4, put_index};
use crate::error::{Error, Result};
use crate::heaps::{BlobHeapBuilder, GuidHeapBuilder, StringsHeapBuilder, UserStringsHeapBuilder};
use crate::metadata::Metadata;
use crate::pdb::PdbStream;
use crate::root::{MetadataRoot, StreamHeader};
use crate::tables::{
    HEAP_BLOB_WIDE, HEAP_GUID_WIDE, HEAP_STRINGS_WIDE, Layout, TableId, TableRows, TablesHeader,
    columns,
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
    Raw(String, Vec<u8>),
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
    /// The version string of the runtime.
    pub version: String,
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
    /// Makes empty metadata with a runtime version string.
    #[must_use]
    pub fn new(version: &str) -> Self {
        Self {
            major_version: 1,
            minor_version: 1,
            reserved: 0,
            version: version.to_string(),
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
    /// # Errors
    ///
    /// Returns an error when a row is not valid.
    pub fn from_metadata(metadata: &Metadata<'_>) -> Result<Self> {
        let root = metadata.root();
        let mut streams = Vec::with_capacity(root.streams.len());
        let mut seen = Vec::new();
        for header in &root.streams {
            let slot = match header.name {
                "#~" | "#-" => StreamSlot::Tables,
                "#Strings" => StreamSlot::Strings,
                "#US" => StreamSlot::UserStrings,
                "#GUID" => StreamSlot::Guid,
                "#Blob" => StreamSlot::Blob,
                "#Pdb" => StreamSlot::Pdb,
                _ => StreamSlot::Raw(String::new(), Vec::new()),
            };
            let slot = if matches!(slot, StreamSlot::Raw(..)) || seen.contains(&slot) {
                let start = header.offset as usize;
                let data = metadata
                    .data()
                    .get(start..start + header.size as usize)
                    .unwrap_or_default();
                StreamSlot::Raw(header.name.to_string(), data.to_vec())
            } else {
                seen.push(slot.clone());
                slot
            };
            streams.push(slot);
        }
        Ok(Self {
            major_version: root.major_version,
            minor_version: root.minor_version,
            reserved: root.reserved,
            version: root.version.to_string(),
            flags: root.flags,
            tables_header: metadata.tables().header().clone(),
            uncompressed: metadata.tables_stream_name() == "#-",
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

    /// Writes the metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when a row holds a value that its column cannot
    /// hold, or a stream is larger than 4 GiB.
    pub fn write(&self) -> Result<Vec<u8>> {
        let tables = self.write_tables()?;
        let pdb = self.pdb.as_ref().map(PdbStream::write);
        let tables_name = if self.uncompressed { "#-" } else { "#~" };
        let mut parts: Vec<(&str, &[u8])> = Vec::with_capacity(self.streams.len());
        for slot in &self.streams {
            let part: (&str, &[u8]) = match slot {
                StreamSlot::Tables => (tables_name, &tables),
                StreamSlot::Strings => ("#Strings", self.strings.as_bytes()),
                StreamSlot::UserStrings => ("#US", self.user_strings.as_bytes()),
                StreamSlot::Guid => ("#GUID", self.guids.as_bytes()),
                StreamSlot::Blob => ("#Blob", self.blobs.as_bytes()),
                StreamSlot::Pdb => ("#Pdb", pdb.as_deref().unwrap_or_default()),
                StreamSlot::Raw(name, data) => (name.as_str(), data),
            };
            parts.push(part);
        }
        let root = MetadataRoot {
            major_version: self.major_version,
            minor_version: self.minor_version,
            reserved: self.reserved,
            version: &self.version,
            flags: self.flags,
            streams: Vec::new(),
        };
        let mut offset = MetadataRoot::header_size(&self.version, parts.iter().map(|p| p.0.len()));
        let mut headers = Vec::with_capacity(parts.len());
        for &(name, data) in &parts {
            let size = data.len().next_multiple_of(4);
            headers.push(StreamHeader {
                offset: to_u32(offset)?,
                size: to_u32(size)?,
                name,
            });
            offset += size;
        }
        let mut out = Vec::with_capacity(offset);
        MetadataRoot::write_header(&mut out, &root, &headers)?;
        for (_, data) in parts {
            out.extend_from_slice(data);
            pad4(&mut out);
        }
        Ok(out)
    }

    /// Writes the tables stream.
    fn write_tables(&self) -> Result<Vec<u8>> {
        let mut header = self.tables_header.clone();
        let wide_heap = |len: usize, flag: u8| if len > 0xFFFF { flag } else { 0 };
        header.heap_sizes |= wide_heap(self.strings.as_bytes().len(), HEAP_STRINGS_WIDE)
            | wide_heap(self.guids.as_bytes().len() / 16, HEAP_GUID_WIDE)
            | wide_heap(self.blobs.as_bytes().len(), HEAP_BLOB_WIDE);
        for &table in TableId::ALL {
            let count = to_u32(self.rows.row_count(table))?;
            let bit = 1u64 << table as u8;
            if count > 0 {
                header.valid |= bit;
            }
            header.row_counts[table as usize] = count;
        }
        let mut out = Vec::new();
        header.write(&mut out);
        let mut sizing = header.row_counts;
        if let Some(pdb) = &self.pdb {
            for (count, &external) in sizing.iter_mut().zip(&pdb.type_system_table_rows) {
                *count = (*count).max(external);
            }
        }
        let wide = self
            .streams
            .iter()
            .any(|slot| matches!(slot, StreamSlot::Raw(name, _) if name == "#JTD"));
        let layout = Layout::compute(
            header.heap_sizes,
            &header.row_counts,
            &sizing,
            wide,
            out.len(),
        );
        for &table in TableId::ALL {
            let widths = layout.table(table).widths;
            for position in 0..self.rows.row_count(table) {
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
                for (column, (&value, &width)) in raw.iter().zip(&widths).enumerate() {
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

#[cfg(test)]
mod tests;
