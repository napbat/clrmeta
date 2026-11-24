//! The borrowed view of the tables stream.

use core::marker::PhantomData;

use crate::bytes::Cursor;
use crate::error::{Error, Result};
use crate::tables::{
    AnyRow, Layout, MAX_COLUMNS, RawRow, TableId, TableLayout, TableRow, TableRows, TablesHeader,
    check_fits, columns, sort_key,
};
use crate::token::{Rid, Token};

/// The tables of a `#~` or `#-` stream, over its borrowed bytes.
#[derive(Debug, Clone)]
pub struct Tables<'a> {
    data: &'a [u8],
    header: TablesHeader,
    layout: Layout,
    wide: bool,
}

impl<'a> Tables<'a> {
    /// Parses a tables stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the header is not valid or the rows do not fit
    /// the stream.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        Self::parse_with(data, None, false)
    }

    /// Parses a tables stream with the options of a portable PDB or of an
    /// edit-and-continue delta.
    ///
    /// `type_system_rows` are the row counts of the tables of the type
    /// system that a portable PDB refers to (the `#Pdb` stream); they set
    /// the widths of the indices into those tables. `wide` makes every index
    /// 4 bytes, as the `#JTD` stream of a minimal delta requires.
    ///
    /// # Errors
    ///
    /// Returns an error when the header is not valid or the rows do not fit
    /// the stream.
    pub fn parse_with(
        data: &'a [u8],
        type_system_rows: Option<&[u32; 64]>,
        wide: bool,
    ) -> Result<Self> {
        let mut cursor = Cursor::new(data, "tables stream");
        let header = TablesHeader::parse(&mut cursor)?;
        let mut sizing = header.row_counts;
        if let Some(external) = type_system_rows {
            for (count, &extern_count) in sizing.iter_mut().zip(external) {
                *count = (*count).max(extern_count);
            }
        }
        let layout = Layout::compute(
            header.heap_sizes,
            &header.row_counts,
            &sizing,
            wide,
            cursor.position(),
        );
        check_fits(&layout, data.len())?;
        Ok(Self {
            data,
            header,
            layout,
            wide,
        })
    }

    /// Returns the header.
    #[must_use]
    pub const fn header(&self) -> &TablesHeader {
        &self.header
    }

    /// Returns the layout of the rows.
    #[must_use]
    pub const fn layout(&self) -> &Layout {
        &self.layout
    }

    /// Returns `true` when every index is 4 bytes (`#JTD`).
    #[must_use]
    pub const fn is_wide(&self) -> bool {
        self.wide
    }

    /// Returns the bytes of the stream.
    #[must_use]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Returns the row count of a table.
    #[must_use]
    pub const fn row_count(&self, table: TableId) -> u32 {
        self.header.row_count(table)
    }

    /// Returns the typed view of the table of `R`.
    #[must_use]
    pub fn table<R: TableRow>(&self) -> Table<'a, R> {
        Table {
            view: self.raw_table(R::TABLE),
            rows: PhantomData,
        }
    }

    /// Returns the untyped view of a table.
    #[must_use]
    pub fn raw_table(&self, table: TableId) -> RawTable<'a> {
        let layout = *self.layout.table(table);
        let data = self
            .data
            .get(layout.offset..layout.offset + layout.size())
            .unwrap_or_default();
        RawTable {
            table,
            data,
            layout,
            sorted: self.header.is_sorted(table),
        }
    }

    /// Reads a row.
    ///
    /// # Errors
    ///
    /// Returns an error when the row is outside the table or a column is
    /// not valid.
    pub fn row<R: TableRow>(&self, rid: Rid<R>) -> Result<R> {
        self.table::<R>().get(rid)
    }

    /// Reads the row of a token.
    ///
    /// # Errors
    ///
    /// Returns an error when the token names no table, the row is outside
    /// the table, or a column is not valid.
    pub fn any_row(&self, token: Token) -> Result<AnyRow> {
        let table = token.table().ok_or(Error::Token {
            token,
            reason: "the token does not name a table",
        })?;
        let view = self.raw_table(table);
        let raw = view.raw(token.row())?;
        AnyRow::from_raw(table, &raw).map_err(|column| view.column_error(token.row(), column))
    }

    /// Copies every row into an owned store.
    ///
    /// # Errors
    ///
    /// Returns an error when a column is not valid.
    pub fn to_rows(&self) -> Result<TableRows> {
        let mut rows = TableRows::default();
        for &table in TableId::ALL {
            let view = self.raw_table(table);
            for row in 1..=view.len() {
                let raw = view.raw(row)?;
                let any = AnyRow::from_raw(table, &raw)
                    .map_err(|column| view.column_error(row, column))?;
                rows.push_any(any);
            }
        }
        Ok(rows)
    }
}

/// The untyped view of one table.
#[derive(Debug, Clone, Copy)]
pub struct RawTable<'a> {
    table: TableId,
    data: &'a [u8],
    layout: TableLayout,
    sorted: bool,
}

impl<'a> RawTable<'a> {
    /// Returns the table.
    #[must_use]
    pub const fn table(&self) -> TableId {
        self.table
    }

    /// Returns the number of rows.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.layout.row_count
    }

    /// Returns `true` when the table has no rows.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.layout.row_count == 0
    }

    /// Returns the layout of the table.
    #[must_use]
    pub const fn layout(&self) -> &TableLayout {
        &self.layout
    }

    /// Returns `true` when the header marks the table as sorted.
    #[must_use]
    pub const fn is_sorted(&self) -> bool {
        self.sorted
    }

    /// Reads the raw values of the columns of a 1-based row.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RowIndex`] when the row is zero or outside the table.
    pub fn raw(&self, row: u32) -> Result<RawRow> {
        if row == 0 || row > self.layout.row_count {
            return Err(Error::RowIndex {
                table: self.table,
                row,
                count: self.layout.row_count,
            });
        }
        Ok(self.raw_in_range(row))
    }

    /// Reads the raw columns of a 1-based row that is in the table. A row
    /// outside the table reads as zeros.
    pub(crate) fn raw_in_range(&self, row: u32) -> RawRow {
        let size = self.layout.row_size as usize;
        let bytes = (row as usize)
            .checked_sub(1)
            .and_then(|index| index.checked_mul(size))
            .and_then(|start| self.data.get(start..start + size))
            .unwrap_or_default();
        let mut raw = [0; MAX_COLUMNS];
        let mut pos = 0;
        for (slot, &width) in raw.iter_mut().zip(&self.layout.widths) {
            let width = usize::from(width);
            let Some(value) = bytes.get(pos..pos + width) else {
                break;
            };
            *slot = value
                .iter()
                .rev()
                .fold(0, |acc, &byte| (acc << 8) | u32::from(byte));
            pos += width;
        }
        raw
    }

    /// Returns the error of a column that is not valid.
    pub(crate) fn column_error(&self, row: u32, column: usize) -> Error {
        Error::Column {
            table: self.table,
            row,
            column: columns(self.table).get(column).map_or("?", |c| c.name),
            reason: "the coded index has a tag that the column does not use",
        }
    }

    /// Returns the rows whose `column` holds `key`. A table that the header
    /// marks as sorted by that column is searched in logarithmic time, and
    /// any other table is scanned.
    #[must_use]
    pub fn rows_with_key(&self, column: usize, key: u32) -> KeyRows<'a> {
        let count = self.layout.row_count;
        if self.sorted && sort_key(self.table) == Some(column) {
            let start = self.partition(column, |value| value < key);
            let end = self.partition(column, |value| value <= key);
            KeyRows {
                table: *self,
                column,
                key,
                next: start + 1,
                end: end + 1,
            }
        } else {
            KeyRows {
                table: *self,
                column,
                key,
                next: 1,
                end: count + 1,
            }
        }
    }

    /// Returns the number of leading rows whose column satisfies `before`.
    fn partition(&self, column: usize, before: impl Fn(u32) -> bool) -> u32 {
        let (mut low, mut high) = (0, self.layout.row_count);
        while low < high {
            let mid = low + (high - low) / 2;
            if before(self.raw_in_range(mid + 1)[column]) {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        low
    }
}

/// The rows of a table whose column holds a key.
#[derive(Debug, Clone)]
pub struct KeyRows<'a> {
    table: RawTable<'a>,
    column: usize,
    key: u32,
    next: u32,
    end: u32,
}

impl Iterator for KeyRows<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        while self.next < self.end {
            let row = self.next;
            self.next += 1;
            if self.table.raw_in_range(row)[self.column] == self.key {
                return Some(row);
            }
        }
        None
    }
}

/// The typed view of one table.
#[derive(Debug, Clone, Copy)]
pub struct Table<'a, R> {
    view: RawTable<'a>,
    rows: PhantomData<fn() -> R>,
}

impl<'a, R: TableRow> Table<'a, R> {
    /// Returns the number of rows.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.view.len()
    }

    /// Returns `true` when the table has no rows.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.view.is_empty()
    }

    /// Returns the untyped view.
    #[must_use]
    pub const fn raw(&self) -> &RawTable<'a> {
        &self.view
    }

    /// Reads a row.
    ///
    /// # Errors
    ///
    /// Returns an error when the row is outside the table or a column is
    /// not valid.
    pub fn get(&self, rid: Rid<R>) -> Result<R> {
        let raw = self.view.raw(rid.row())?;
        R::from_raw(&raw).map_err(|column| self.view.column_error(rid.row(), column))
    }

    /// Iterates over the rows in order.
    #[must_use]
    pub fn iter(&self) -> TableIter<'a, R> {
        TableIter {
            table: *self,
            next: 1,
        }
    }

    /// Returns the rows whose column holds a key; see
    /// [`RawTable::rows_with_key`].
    pub fn rows_with_key(&self, column: usize, key: u32) -> impl Iterator<Item = Rid<R>> + 'a {
        self.view.rows_with_key(column, key).map(Rid::new)
    }
}

impl<'a, R: TableRow> IntoIterator for &Table<'a, R> {
    type Item = Result<(Rid<R>, R)>;
    type IntoIter = TableIter<'a, R>;

    fn into_iter(self) -> TableIter<'a, R> {
        self.iter()
    }
}

/// The iterator over the rows of a table.
#[derive(Debug, Clone)]
pub struct TableIter<'a, R> {
    table: Table<'a, R>,
    next: u32,
}

impl<R: TableRow> Iterator for TableIter<'_, R> {
    type Item = Result<(Rid<R>, R)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next > self.table.len() {
            return None;
        }
        let rid = Rid::new(self.next);
        self.next += 1;
        Some(self.table.get(rid).map(|row| (rid, row)))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = (self.table.len() + 1 - self.next) as usize;
        (left, Some(left))
    }
}

impl<R: TableRow> ExactSizeIterator for TableIter<'_, R> {}
