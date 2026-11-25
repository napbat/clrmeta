//! The metadata of a module: the root, the heaps and the tables, with the
//! lookups that follow the links between the tables.

use alloc::borrow::Cow;
use alloc::string::String;

use crate::error::{Error, Result};
use crate::heaps::{BlobHeap, GuidHeap, StringsHeap, UserStringsHeap};
use crate::pdb::PdbStream;
use crate::root::{MetadataRoot, StreamSelection};
use crate::tables::{AnyRow, TableId, TableRow, Tables};
use crate::token::Token;

mod lists;
mod names;
mod owners;

pub use lists::RowList;
pub use names::TypeName;

/// The metadata of a module, over its borrowed bytes.
///
/// The bytes start at the metadata root ("BSJB"): the range that the CLI
/// header of a PE image names. Every read is checked: a malformed file
/// returns an error, never a panic.
///
/// The reader reads what the runtime reads and ignores what the runtime
/// ignores, so it reads the files of obfuscators that the runtime loads.
/// [`Metadata::validate`] reports what ECMA-335 does not allow.
#[derive(Debug, Clone)]
pub struct Metadata<'a> {
    data: &'a [u8],
    root: MetadataRoot<'a>,
    selection: StreamSelection,
    tables: Tables<'a>,
    strings: StringsHeap<'a>,
    user_strings: UserStringsHeap<'a>,
    guids: GuidHeap<'a>,
    blobs: BlobHeap<'a>,
    pdb: Option<PdbStream>,
}

impl<'a> Metadata<'a> {
    /// Parses metadata from the first byte of its root.
    ///
    /// The reader takes the streams that the runtime takes (see
    /// [`StreamSelection`]): the last stream of a name in metadata with a
    /// `#~` stream, and the first stream of a name, without case, in
    /// metadata with a `#-` or a `#Schema` stream. It ignores the other
    /// streams. A missing heap reads as empty. A `#Pdb` stream makes the
    /// reader size the indices into the type system tables from its row
    /// counts, and a `#JTD` stream in metadata with a `#-` or a `#Schema`
    /// stream makes every index 4 bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the root is not valid, the tables stream is
    /// missing or not valid, or a stream lies outside `data`.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let root = MetadataRoot::parse(data)?;
        let selection = root.selection();
        let stream = |index: Option<usize>| index.map(|index| root.stream_data(data, index));
        let tables_data = stream(selection.tables).ok_or(Error::MissingStream("#~"))?;
        let pdb = stream(selection.pdb).map(PdbStream::parse).transpose()?;
        let tables = Tables::parse_with(
            tables_data,
            pdb.as_ref().map(|pdb| &pdb.type_system_table_rows),
            selection.jtd.is_some(),
        )?;
        let guids = selection.guids.map_or_else(GuidHeap::default, |index| {
            let end = root.streams.get(index).map_or(data.len(), |header| {
                header.offset as usize + header.size as usize
            });
            let after = data.get(end..).unwrap_or_default();
            GuidHeap::with_bytes_after(root.stream_data(data, index), after)
        });
        Ok(Self {
            data,
            selection,
            tables,
            strings: StringsHeap::new(stream(selection.strings).unwrap_or_default()),
            user_strings: UserStringsHeap::new(stream(selection.user_strings).unwrap_or_default()),
            guids,
            blobs: BlobHeap::new(stream(selection.blobs).unwrap_or_default()),
            pdb,
            root,
        })
    }

    /// Returns the bytes of the metadata.
    #[must_use]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Returns the root.
    #[must_use]
    pub const fn root(&self) -> &MetadataRoot<'a> {
        &self.root
    }

    /// Returns the streams that the reader takes, by their position in the
    /// stream headers of the root.
    #[must_use]
    pub const fn stream_selection(&self) -> &StreamSelection {
        &self.selection
    }

    /// Returns the version string of the runtime. A byte sequence that is
    /// not UTF-8 becomes U+FFFD; the runtime does not check it.
    #[must_use]
    pub fn version(&self) -> Cow<'a, str> {
        String::from_utf8_lossy(self.root.version_string())
    }

    /// Returns the name of the tables stream as the stream header holds it:
    /// `#~`, or `#-` for unoptimized metadata.
    #[must_use]
    pub fn tables_stream_name(&self) -> &'a [u8] {
        self.selection
            .tables
            .and_then(|index| self.root.streams.get(index))
            .map_or(&[], |header| header.name)
    }

    /// Returns the tables.
    #[must_use]
    pub const fn tables(&self) -> &Tables<'a> {
        &self.tables
    }

    /// Returns the `#Strings` heap.
    #[must_use]
    pub const fn strings(&self) -> &StringsHeap<'a> {
        &self.strings
    }

    /// Returns the `#US` heap.
    #[must_use]
    pub const fn user_strings(&self) -> &UserStringsHeap<'a> {
        &self.user_strings
    }

    /// Returns the `#GUID` heap.
    #[must_use]
    pub const fn guids(&self) -> &GuidHeap<'a> {
        &self.guids
    }

    /// Returns the `#Blob` heap.
    #[must_use]
    pub const fn blobs(&self) -> &BlobHeap<'a> {
        &self.blobs
    }

    /// Returns the `#Pdb` stream of a portable PDB.
    #[must_use]
    pub const fn pdb(&self) -> Option<&PdbStream> {
        self.pdb.as_ref()
    }

    /// Reads the row of a token.
    ///
    /// # Errors
    ///
    /// Returns an error when the token names no table, the row is outside
    /// its table, or a column is not valid.
    pub fn row(&self, token: Token) -> Result<AnyRow> {
        self.tables.any_row(token)
    }

    /// Reads the row of a token of the table of `R`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Token`] when the token names another table, and the
    /// errors of [`Tables::row`].
    pub fn typed_row<R: TableRow>(&self, token: Token) -> Result<R> {
        let rid = crate::Rid::<R>::from_token(token).ok_or(Error::Token {
            token,
            reason: "the token names another table",
        })?;
        self.tables.row(rid)
    }

    /// Returns `true` when the `Ptr` table of `table` has rows, so the list
    /// columns that point into `table` index the `Ptr` table.
    #[must_use]
    pub fn has_indirection(&self, table: TableId) -> bool {
        let ptr = match table {
            TableId::Field => TableId::FieldPtr,
            TableId::MethodDef => TableId::MethodPtr,
            TableId::Param => TableId::ParamPtr,
            TableId::Event => TableId::EventPtr,
            TableId::Property => TableId::PropertyPtr,
            _ => return false,
        };
        self.tables.row_count(ptr) > 0
    }
}

#[cfg(test)]
mod tests;
