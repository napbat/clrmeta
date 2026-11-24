//! The metadata of a module: the root, the heaps and the tables, with the
//! lookups that follow the links between the tables.

use crate::error::{Error, Result};
use crate::heaps::{BlobHeap, GuidHeap, StringsHeap, UserStringsHeap};
use crate::pdb::PdbStream;
use crate::root::MetadataRoot;
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
#[derive(Debug, Clone)]
pub struct Metadata<'a> {
    data: &'a [u8],
    root: MetadataRoot<'a>,
    tables_stream: &'a str,
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
    /// The heaps are optional: a missing heap reads as empty. The first
    /// stream of each name counts. A `#Pdb` stream makes the reader size the
    /// indices into the type system tables from its row counts, and a
    /// `#JTD` stream makes every index 4 bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the root is not valid, the tables stream is
    /// missing or not valid, or a stream lies outside `data`.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let root = MetadataRoot::parse(data)?;
        let stream = |name: &str| {
            root.stream(name).map(|header| {
                let start = header.offset as usize;
                &data[start..start + header.size as usize]
            })
        };
        let (tables_stream, tables_data) = ["#~", "#-"]
            .into_iter()
            .find_map(|name| stream(name).map(|bytes| (name, bytes)))
            .ok_or(Error::MissingStream("#~"))?;
        let pdb = stream("#Pdb").map(PdbStream::parse).transpose()?;
        let tables = Tables::parse_with(
            tables_data,
            pdb.as_ref().map(|pdb| &pdb.type_system_table_rows),
            root.stream("#JTD").is_some(),
        )?;
        Ok(Self {
            data,
            tables_stream,
            tables,
            strings: StringsHeap::new(stream("#Strings").unwrap_or_default()),
            user_strings: UserStringsHeap::new(stream("#US").unwrap_or_default()),
            guids: GuidHeap::new(stream("#GUID").unwrap_or_default()),
            blobs: BlobHeap::new(stream("#Blob").unwrap_or_default()),
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

    /// Returns the version string of the runtime.
    #[must_use]
    pub const fn version(&self) -> &'a str {
        self.root.version
    }

    /// Returns the name of the tables stream: `#~`, or `#-` for unoptimized
    /// metadata.
    #[must_use]
    pub const fn tables_stream_name(&self) -> &'a str {
        self.tables_stream
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
