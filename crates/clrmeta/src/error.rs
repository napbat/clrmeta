//! The errors of the reader and the writer.

use core::fmt;

use crate::tables::TableId;
use crate::token::Token;

/// The result of an operation of this crate.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// The heaps of the metadata (ECMA-335 II.24.2.2 to II.24.2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HeapKind {
    /// The `#Strings` heap of UTF-8 identifiers.
    Strings,
    /// The `#US` heap of UTF-16 user strings.
    UserStrings,
    /// The `#GUID` heap.
    Guid,
    /// The `#Blob` heap.
    Blob,
}

impl HeapKind {
    /// Returns the stream name of the heap.
    #[must_use]
    pub const fn stream_name(self) -> &'static str {
        match self {
            Self::Strings => "#Strings",
            Self::UserStrings => "#US",
            Self::Guid => "#GUID",
            Self::Blob => "#Blob",
        }
    }
}

/// An error of the reader or the writer.
///
/// Each variant names the structure, the table row, the heap index or the
/// byte offset where the error occurs. An offset is relative to the start of
/// the bytes that the failing call received.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The bytes end before the structure ends.
    Truncated {
        /// The structure that the reader reads.
        structure: &'static str,
        /// The offset of the read that fails.
        offset: usize,
        /// The number of bytes that the read needs.
        needed: usize,
    },
    /// The structure holds a value that ECMA-335 does not allow.
    Malformed {
        /// The structure that the reader reads.
        structure: &'static str,
        /// The offset of the value.
        offset: usize,
        /// Why the value is not valid.
        reason: &'static str,
    },
    /// The metadata has no stream with this name.
    MissingStream(&'static str),
    /// A heap index points outside its heap.
    HeapIndex {
        /// The heap.
        heap: HeapKind,
        /// The index.
        index: u32,
    },
    /// A row index is zero or larger than the row count of its table.
    RowIndex {
        /// The table.
        table: TableId,
        /// The 1-based row index.
        row: u32,
        /// The row count of the table.
        count: u32,
    },
    /// A column of a row holds a value that is not valid.
    Column {
        /// The table.
        table: TableId,
        /// The 1-based row index.
        row: u32,
        /// The name of the column.
        column: &'static str,
        /// Why the value is not valid.
        reason: &'static str,
    },
    /// The token does not name a table or a heap that the operation accepts.
    Token {
        /// The token.
        token: Token,
        /// Why the operation refuses the token.
        reason: &'static str,
    },
    /// The writer cannot store a value in the field that holds it.
    Overflow {
        /// The structure that the writer writes.
        structure: &'static str,
        /// The value that does not fit.
        value: u64,
    },
    /// A custom attribute value has an enum type that the resolver does not know.
    UnresolvedEnum {
        /// The offset of the value in its blob.
        offset: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                structure,
                offset,
                needed,
            } => write!(
                f,
                "{structure}: the data ends at offset {offset:#x}, {needed} more bytes are necessary"
            ),
            Self::Malformed {
                structure,
                offset,
                reason,
            } => write!(f, "{structure} at offset {offset:#x}: {reason}"),
            Self::MissingStream(name) => write!(f, "the metadata has no {name} stream"),
            Self::HeapIndex { heap, index } => {
                write!(
                    f,
                    "index {index:#x} is outside the {} heap",
                    heap.stream_name()
                )
            }
            Self::RowIndex { table, row, count } => write!(
                f,
                "row {row} is outside the {} table of {count} rows",
                table.name()
            ),
            Self::Column {
                table,
                row,
                column,
                reason,
            } => write!(f, "{} row {row}, column {column}: {reason}", table.name()),
            Self::Token { token, reason } => write!(f, "token {token}: {reason}"),
            Self::Overflow { structure, value } => {
                write!(
                    f,
                    "{structure}: the value {value:#x} does not fit its field"
                )
            }
            Self::UnresolvedEnum { offset } => write!(
                f,
                "custom attribute value at offset {offset:#x}: the underlying type of the enum is not known"
            ),
        }
    }
}

impl core::error::Error for Error {}
