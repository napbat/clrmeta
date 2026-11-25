//! The macro that makes the table identifiers, the row types, the row enum
//! and the owned row store from one schema.

/// Defines the tables. Each table states its identifier, its row type, the
/// name of its rows in [`TableRows`](crate::tables::TableRows), and its
/// columns, each with a field type and a [`ColumnKind`](crate::tables::ColumnKind).
macro_rules! define_tables {
    ($(
        $(#[doc = $doc:literal])+
        $id:ident = $value:literal, $row:ident, $rows:ident {
            $(
                $(#[doc = $field_doc:literal])+
                $field:ident: $ty:ty = $kind:expr
            ),+ $(,)?
        }
    )+) => {
        // The identifiers live in `clrmeta-model`; the schema must agree.
        $(const _: () = assert!(TableId::$id as u8 == $value);)+

        /// Returns the columns of a table.
        #[must_use]
        pub const fn columns(table: TableId) -> &'static [Column] {
            match table {
                $(TableId::$id => <$row as TableRow>::COLUMNS,)+
            }
        }

        $(
            $(#[doc = $doc])+
            #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
            pub struct $row {
                $(
                    $(#[doc = $field_doc])+
                    pub $field: $ty,
                )+
            }

            impl TableRow for $row {
                const TABLE: TableId = TableId::$id;
                const COLUMNS: &'static [Column] = &[
                    $(Column { name: stringify!($field), kind: $kind }),+
                ];

                fn from_raw(raw: &RawRow) -> Result<Self, usize> {
                    let mut columns = Self::COLUMNS.iter().zip(raw).enumerate();
                    Ok(Self {
                        $(
                            $field: {
                                let (position, (column, &value)) =
                                    columns.next().ok_or(MAX_COLUMNS)?;
                                <$ty as ColumnValue>::from_raw(value, column.kind)
                                    .ok_or(position)?
                            },
                        )+
                    })
                }

                fn to_raw(&self) -> Result<RawRow, usize> {
                    let mut raw = [0; MAX_COLUMNS];
                    let mut slots = raw.iter_mut().zip(Self::COLUMNS).enumerate();
                    $(
                        let (position, (slot, column)) = slots.next().ok_or(MAX_COLUMNS)?;
                        *slot = ColumnValue::to_raw(self.$field, column.kind).ok_or(position)?;
                    )+
                    Ok(raw)
                }

                fn rows(store: &TableRows) -> &[Self] {
                    &store.$rows
                }

                fn rows_mut(store: &mut TableRows) -> &mut Vec<Self> {
                    &mut store.$rows
                }
            }
        )+

        /// A row of any table.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum AnyRow {
            $(
                $(#[doc = $doc])+
                $id($row),
            )+
        }

        impl AnyRow {
            /// Returns the table of the row.
            #[must_use]
            pub const fn table(&self) -> TableId {
                match self {
                    $(Self::$id(_) => TableId::$id,)+
                }
            }

            /// Decodes the raw values of a row of `table`. An error holds the
            /// position of the column that is not valid.
            ///
            /// # Errors
            ///
            /// Returns the position of a column whose value is not valid.
            pub fn from_raw(table: TableId, raw: &RawRow) -> Result<Self, usize> {
                Ok(match table {
                    $(TableId::$id => Self::$id(<$row as TableRow>::from_raw(raw)?),)+
                })
            }

            /// Encodes the row to its raw values.
            ///
            /// # Errors
            ///
            /// Returns the position of a column that cannot hold its value.
            pub fn to_raw(&self) -> Result<RawRow, usize> {
                match self {
                    $(Self::$id(row) => row.to_raw(),)+
                }
            }
        }

        /// The owned rows of every table, for the writer.
        #[derive(Debug, Clone, Default, PartialEq, Eq)]
        pub struct TableRows {
            $(
                $(#[doc = $doc])+
                pub $rows: Vec<$row>,
            )+
        }

        impl TableRows {
            /// Returns the number of rows of `table`.
            #[must_use]
            pub fn row_count(&self, table: TableId) -> usize {
                match table {
                    $(TableId::$id => self.$rows.len(),)+
                }
            }

            /// Returns the row at the 0-based `position` of `table`.
            #[must_use]
            pub fn any_row(&self, table: TableId, position: usize) -> Option<AnyRow> {
                match table {
                    $(TableId::$id => self.$rows.get(position).copied().map(AnyRow::$id),)+
                }
            }

            /// Appends a row to its table and returns its 1-based index.
            pub fn push_any(&mut self, row: AnyRow) -> u32 {
                let len = match row {
                    $(AnyRow::$id(row) => {
                        self.$rows.push(row);
                        self.$rows.len()
                    })+
                };
                u32::try_from(len).unwrap_or(u32::MAX)
            }

            /// Replaces the row at the 0-based `position` of the table of
            /// `row`. Returns `false` when the table has no such row.
            pub fn set_any(&mut self, position: usize, row: AnyRow) -> bool {
                match row {
                    $(AnyRow::$id(row) => self
                        .$rows
                        .get_mut(position)
                        .map(|slot| *slot = row)
                        .is_some(),)+
                }
            }
        }
    };
}

pub(crate) use define_tables;
