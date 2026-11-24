//! The validation of the links between the tables and the heaps.

use alloc::vec::Vec;

use clrmeta_model::element_type as et;

use crate::error::Error;
use crate::heaps::{BlobIndex, GuidIndex, StringIndex};
use crate::marshal::MarshalDescriptor;
use crate::metadata::Metadata;
use crate::signature::{
    FieldSig, MemberSignature, MethodSig, MethodSpecSig, PropertySig, Signature,
    StandAloneSignature, TypeSig,
};
use crate::tables::{ColumnKind, RawRow, TableId, columns, list_columns, sort_key};

/// A problem that [`Metadata::validate`] finds in a column of a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    /// The table.
    pub table: TableId,
    /// The 1-based row.
    pub row: u32,
    /// The name of the column.
    pub column: &'static str,
    /// The problem.
    pub error: Error,
}

impl Metadata<'_> {
    /// Checks every row of every table: the coded index tags, the indices
    /// into the tables and the heaps, the UTF-8 of the names, the
    /// signatures, the marshalling descriptors, the sizes of the constants,
    /// the order of the list columns, and the order of the tables that
    /// ECMA-335 requires to be sorted. Returns the problems in table order.
    #[must_use]
    pub fn validate(&self) -> Vec<Issue> {
        let mut issues = Vec::new();
        for &table in TableId::ALL {
            let view = self.tables().raw_table(table);
            let mut previous: Option<RawRow> = None;
            for row in 1..=view.len() {
                let raw = view.raw_in_range(row);
                let mut report = |column: usize, error: Error| {
                    issues.push(Issue {
                        table,
                        row,
                        column: columns(table).get(column).map_or("?", |c| c.name),
                        error,
                    });
                };
                for (position, column) in columns(table).iter().enumerate() {
                    if let Err(error) =
                        self.check_column(table, position, column.kind, raw[position])
                    {
                        report(position, error);
                    }
                }
                if let Err(error) = self.check_blob_content(table, &raw) {
                    report(blob_column(table), error);
                }
                if let Some(previous) = previous {
                    order_issues(table, row, &previous, &raw, &mut report);
                }
                previous = Some(raw);
            }
        }
        issues
    }

    fn check_column(
        &self,
        table: TableId,
        position: usize,
        kind: ColumnKind,
        value: u32,
    ) -> Result<(), Error> {
        let column = columns(table)[position].name;
        let reject = |reason| Error::Column {
            table,
            row: 0,
            column,
            reason,
        };
        match kind {
            ColumnKind::U16 | ColumnKind::U32 => Ok(()),
            ColumnKind::Strings => self.strings().get(StringIndex(value)).map(|_| ()),
            ColumnKind::Guid => self.guids().get(GuidIndex(value)).map(|_| ()),
            ColumnKind::Blob => self.blobs().get(BlobIndex(value)).map(|_| ()),
            ColumnKind::Table(target) => {
                let count = self.tables().row_count(target);
                let is_list = list_columns(table)
                    .iter()
                    .any(|list| list.column == position);
                let limit = if is_list {
                    list_limit(self, table, position, count) + 1
                } else {
                    count
                };
                if value > limit {
                    Err(reject("the row is outside the target table"))
                } else if is_list && value == 0 {
                    Err(reject("a list starts at row 0"))
                } else {
                    Ok(())
                }
            }
            ColumnKind::Coded(coded) => {
                let token = coded.decode(value).ok_or_else(|| {
                    reject("the coded index has a tag that the column does not use")
                })?;
                let target = token
                    .table()
                    .ok_or_else(|| reject("the coded index names no table"))?;
                if token.row() > self.tables().row_count(target) {
                    Err(reject("the row is outside the target table"))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Parses the blob of a row whose blob has a format of its own.
    fn check_blob_content(&self, table: TableId, raw: &RawRow) -> Result<(), Error> {
        let blob = |position: usize| self.blobs().get(BlobIndex(raw[position]));
        match table {
            TableId::Field => FieldSig::parse(blob(2)?).map(|_| ()),
            TableId::MethodDef => MethodSig::parse(blob(4)?).map(|_| ()),
            TableId::MemberRef => MemberSignature::parse(blob(2)?).map(|_| ()),
            TableId::StandAloneSig => StandAloneSignature::parse(blob(0)?).map(|_| ()),
            TableId::Property => PropertySig::parse(blob(2)?).map(|_| ()),
            TableId::TypeSpec => TypeSig::parse(blob(0)?).map(|_| ()),
            TableId::MethodSpec => MethodSpecSig::parse(blob(1)?).map(|_| ()),
            TableId::FieldMarshal => MarshalDescriptor::parse(blob(1)?).map(|_| ()),
            TableId::Constant => check_constant(raw[0].to_le_bytes()[0], blob(2)?),
            _ => Ok(()),
        }
    }
}

/// Returns the position of the blob column that `check_blob_content` reads.
fn blob_column(table: TableId) -> usize {
    match table {
        TableId::Field | TableId::MemberRef | TableId::Property | TableId::Constant => 2,
        TableId::MethodDef => 4,
        TableId::MethodSpec | TableId::FieldMarshal => 1,
        _ => 0,
    }
}

/// Returns the row count that bounds a list column: the count of the `Ptr`
/// table when it has rows.
fn list_limit(metadata: &Metadata<'_>, table: TableId, position: usize, count: u32) -> u32 {
    list_columns(table)
        .iter()
        .find(|list| list.column == position)
        .and_then(|list| list.indirection)
        .map(|ptr| metadata.tables().row_count(ptr))
        .filter(|&ptr_count| ptr_count > 0)
        .unwrap_or(count)
}

/// Checks the size of a constant against its element type (II.22.9).
fn check_constant(element: u8, value: &[u8]) -> Result<(), Error> {
    let expected = match element {
        et::BOOLEAN | et::I1 | et::U1 => Some(1),
        et::CHAR | et::I2 | et::U2 => Some(2),
        et::I4 | et::U4 | et::R4 | et::CLASS => Some(4),
        et::I8 | et::U8 | et::R8 => Some(8),
        et::STRING => None,
        _ => {
            return Err(Error::Malformed {
                structure: "constant",
                offset: 0,
                reason: "the element type cannot be a constant",
            });
        }
    };
    match expected {
        Some(len) if len != value.len() => Err(Error::Malformed {
            structure: "constant",
            offset: 0,
            reason: "the size of the value does not match its element type",
        }),
        None if !value.len().is_multiple_of(2) => Err(Error::Malformed {
            structure: "constant",
            offset: 0,
            reason: "a string constant has an odd number of bytes",
        }),
        _ => Ok(()),
    }
}

/// Checks the order of a row against the row before it: list columns do
/// not decrease, and a table that ECMA-335 requires to be sorted is sorted.
fn order_issues(
    table: TableId,
    row: u32,
    previous: &RawRow,
    raw: &RawRow,
    report: &mut impl FnMut(usize, Error),
) {
    for list in list_columns(table) {
        if raw[list.column] < previous[list.column] {
            report(
                list.column,
                Error::Column {
                    table,
                    row,
                    column: columns(table)[list.column].name,
                    reason: "the list starts before the list of the row before",
                },
            );
        }
    }
    if let Some(key) = sort_key(table)
        && raw[key] < previous[key]
    {
        report(
            key,
            Error::Column {
                table,
                row,
                column: columns(table)[key].name,
                reason: "the table is not sorted by this column",
            },
        );
    }
}
