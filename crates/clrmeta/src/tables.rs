//! The metadata tables (ECMA-335 II.22 and II.24.2.6).
//!
//! [`Tables`] reads rows on demand from the borrowed bytes of the tables
//! stream. Each table has a row type ([`TypeDefRow`], [`MethodDefRow`], …)
//! that implements [`TableRow`], and [`Rid`](crate::Rid) indexes the rows
//! of one table. Coded indices decode to [`Token`](crate::Token)s.
//! [`TableRows`] holds owned rows for the writer.

use alloc::vec::Vec;
use core::fmt::Debug;

mod coded;
mod column;
mod define;
mod header;
mod schema;
mod view;

pub use clrmeta_model::TableId;
pub use coded::CodedIndexKind;
pub use column::{Column, ColumnKind, MAX_COLUMNS, RawRow};
pub use header::{
    HEAP_BLOB_WIDE, HEAP_DELTA_ONLY, HEAP_EXTRA_DATA, HEAP_GUID_WIDE, HEAP_HAS_DELETE,
    HEAP_STRINGS_WIDE, Layout, TableLayout, TablesHeader,
};
pub use schema::*;
pub use view::{KeyRows, RawTable, Table, TableIter, Tables};

pub(crate) use header::check_fits;

/// A row type of one table.
pub trait TableRow: Copy + Debug + Sized + 'static {
    /// The table of the rows.
    const TABLE: TableId;
    /// The columns of the table.
    const COLUMNS: &'static [Column];

    /// Decodes the raw values of the columns.
    ///
    /// # Errors
    ///
    /// Returns the position of a column whose value is not valid.
    fn from_raw(raw: &RawRow) -> Result<Self, usize>;

    /// Encodes the row to the raw values of its columns.
    ///
    /// # Errors
    ///
    /// Returns the position of a column that cannot hold its value.
    fn to_raw(&self) -> Result<RawRow, usize>;

    /// Returns the rows of the table in an owned store.
    fn rows(store: &TableRows) -> &[Self];

    /// Returns the mutable rows of the table in an owned store.
    fn rows_mut(store: &mut TableRows) -> &mut Vec<Self>;
}

/// Returns the position of the column that ECMA-335 requires a table to be
/// sorted by, or `None` for a table without a sort requirement (II.22).
///
/// `GenericParam` sorts by its owner and then by its number, and
/// `InterfaceImpl` by its class and then by its interface; the key is the
/// first column of the two.
#[must_use]
pub const fn sort_key(table: TableId) -> Option<usize> {
    match table {
        TableId::CustomAttribute
        | TableId::FieldMarshal
        | TableId::GenericParamConstraint
        | TableId::InterfaceImpl
        | TableId::MethodImpl
        | TableId::NestedClass
        | TableId::LocalScope
        | TableId::StateMachineMethod
        | TableId::CustomDebugInformation => Some(0),
        TableId::Constant
        | TableId::DeclSecurity
        | TableId::FieldLayout
        | TableId::FieldRva
        | TableId::ImplMap => Some(1),
        TableId::ClassLayout | TableId::GenericParam | TableId::MethodSemantics => Some(2),
        _ => None,
    }
}

/// A list column: the column of a table that holds the first row of a run
/// of rows of another table. The run ends at the first row of the next row,
/// or at the end of the target table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListColumn {
    /// The position of the column.
    pub column: usize,
    /// The table of the run.
    pub target: TableId,
    /// The indirection table of unoptimized metadata, when it exists.
    pub indirection: Option<TableId>,
}

/// Returns the list columns of a table.
#[must_use]
pub const fn list_columns(table: TableId) -> &'static [ListColumn] {
    const fn list(column: usize, target: TableId, indirection: Option<TableId>) -> ListColumn {
        ListColumn {
            column,
            target,
            indirection,
        }
    }
    const TYPE_DEF: [ListColumn; 2] = [
        list(4, TableId::Field, Some(TableId::FieldPtr)),
        list(5, TableId::MethodDef, Some(TableId::MethodPtr)),
    ];
    const METHOD_DEF: [ListColumn; 1] = [list(5, TableId::Param, Some(TableId::ParamPtr))];
    const EVENT_MAP: [ListColumn; 1] = [list(1, TableId::Event, Some(TableId::EventPtr))];
    const PROPERTY_MAP: [ListColumn; 1] = [list(1, TableId::Property, Some(TableId::PropertyPtr))];
    const LOCAL_SCOPE: [ListColumn; 2] = [
        list(2, TableId::LocalVariable, None),
        list(3, TableId::LocalConstant, None),
    ];
    match table {
        TableId::TypeDef => &TYPE_DEF,
        TableId::MethodDef => &METHOD_DEF,
        TableId::EventMap => &EVENT_MAP,
        TableId::PropertyMap => &PROPERTY_MAP,
        TableId::LocalScope => &LOCAL_SCOPE,
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_table_has_columns_that_fit_a_raw_row() {
        for &table in TableId::ALL {
            let count = columns(table).len();
            assert!((1..=MAX_COLUMNS).contains(&count), "{}", table.name());
            if let Some(key) = sort_key(table) {
                assert!(key < count);
            }
            for list in list_columns(table) {
                assert_eq!(
                    columns(table)[list.column].kind,
                    ColumnKind::Table(list.target)
                );
            }
        }
    }

    #[test]
    fn a_row_converts_to_raw_values_and_back() {
        let row = TypeDefRow {
            flags: 0x0010_0001,
            type_name: crate::heaps::StringIndex(5),
            type_namespace: crate::heaps::StringIndex(9),
            extends: crate::Token::new(TableId::TypeRef, 3),
            field_list: crate::Rid::new(1),
            method_list: crate::Rid::new(2),
        };
        let raw = row.to_raw().unwrap();
        assert_eq!(raw[..6], [0x0010_0001, 5, 9, (3 << 2) | 1, 1, 2]);
        assert_eq!(TypeDefRow::from_raw(&raw), Ok(row));
        let any = AnyRow::from_raw(TableId::TypeDef, &raw).unwrap();
        assert_eq!(any, AnyRow::TypeDef(row));
        let mut bad = row;
        bad.extends = crate::Token::new(TableId::MethodDef, 1);
        assert_eq!(bad.to_raw(), Err(3));
        let mut ctor = raw;
        ctor[1] = 0;
        assert_eq!(CustomAttributeRow::from_raw(&ctor), Err(1));
    }
}
