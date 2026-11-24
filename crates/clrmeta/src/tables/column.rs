//! The columns of the tables and the conversion of their raw values.

use crate::heaps::{BlobIndex, GuidIndex, StringIndex};
use crate::tables::{CodedIndexKind, TableId};
use crate::token::{Rid, Token};

/// The largest number of columns of a table (`Assembly` and `AssemblyRef`).
pub const MAX_COLUMNS: usize = 9;

/// The raw values of the columns of one row. A column after the last column
/// of the table holds zero.
pub type RawRow = [u32; MAX_COLUMNS];

/// The kind of value that a column holds, which sets its width.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ColumnKind {
    /// A 2-byte constant.
    U16,
    /// A 4-byte constant.
    U32,
    /// An index into the `#Strings` heap.
    Strings,
    /// An index into the `#GUID` heap.
    Guid,
    /// An index into the `#Blob` heap.
    Blob,
    /// A 1-based index into one table.
    Table(TableId),
    /// A coded index into one of several tables.
    Coded(CodedIndexKind),
}

/// A column of a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Column {
    /// The name of the column in ECMA-335, in snake case.
    pub name: &'static str,
    /// The kind of value.
    pub kind: ColumnKind,
}

/// Conversion between the raw value of a column and the field of a row.
pub(crate) trait ColumnValue: Sized {
    /// Converts a raw value. Returns `None` when the value is not valid for
    /// the column (a coded index with an unused tag).
    fn from_raw(raw: u32, kind: ColumnKind) -> Option<Self>;

    /// Converts the field to its raw value. Returns `None` when the column
    /// cannot hold it (a token of a table that the coded index cannot name).
    fn to_raw(self, kind: ColumnKind) -> Option<u32>;
}

impl ColumnValue for u16 {
    fn from_raw(raw: u32, _: ColumnKind) -> Option<Self> {
        Self::try_from(raw).ok()
    }

    fn to_raw(self, _: ColumnKind) -> Option<u32> {
        Some(u32::from(self))
    }
}

impl ColumnValue for u32 {
    fn from_raw(raw: u32, _: ColumnKind) -> Option<Self> {
        Some(raw)
    }

    fn to_raw(self, _: ColumnKind) -> Option<u32> {
        Some(self)
    }
}

impl ColumnValue for StringIndex {
    fn from_raw(raw: u32, _: ColumnKind) -> Option<Self> {
        Some(Self(raw))
    }

    fn to_raw(self, _: ColumnKind) -> Option<u32> {
        Some(self.0)
    }
}

impl ColumnValue for GuidIndex {
    fn from_raw(raw: u32, _: ColumnKind) -> Option<Self> {
        Some(Self(raw))
    }

    fn to_raw(self, _: ColumnKind) -> Option<u32> {
        Some(self.0)
    }
}

impl ColumnValue for BlobIndex {
    fn from_raw(raw: u32, _: ColumnKind) -> Option<Self> {
        Some(Self(raw))
    }

    fn to_raw(self, _: ColumnKind) -> Option<u32> {
        Some(self.0)
    }
}

impl<R> ColumnValue for Rid<R> {
    fn from_raw(raw: u32, _: ColumnKind) -> Option<Self> {
        Some(Self::new(raw))
    }

    fn to_raw(self, _: ColumnKind) -> Option<u32> {
        Some(self.row())
    }
}

impl ColumnValue for Token {
    fn from_raw(raw: u32, kind: ColumnKind) -> Option<Self> {
        match kind {
            ColumnKind::Coded(coded) => coded.decode(raw),
            _ => Some(Self(raw)),
        }
    }

    fn to_raw(self, kind: ColumnKind) -> Option<u32> {
        match kind {
            // A null token of a table that the kind cannot name (the
            // default token) is the null coded index.
            ColumnKind::Coded(coded) => coded.encode(self).or_else(|| self.is_null().then_some(0)),
            _ => Some(self.0),
        }
    }
}
