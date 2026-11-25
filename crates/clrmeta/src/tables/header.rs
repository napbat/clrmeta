//! The header of the tables stream (II.24.2.6) and the layout of the rows.

use alloc::vec::Vec;

use crate::bytes::{Cursor, put_u32, put_u64};
use crate::error::{Error, Result};
use crate::tables::{CodedIndexKind, ColumnKind, MAX_COLUMNS, TableId, columns};

/// The `heap_sizes` bit: indices into `#Strings` are 4 bytes.
pub const HEAP_STRINGS_WIDE: u8 = 0x01;
/// The `heap_sizes` bit: indices into `#GUID` are 4 bytes.
pub const HEAP_GUID_WIDE: u8 = 0x02;
/// The `heap_sizes` bit: indices into `#Blob` are 4 bytes.
pub const HEAP_BLOB_WIDE: u8 = 0x04;
/// The `heap_sizes` bit of an edit-and-continue delta.
pub const HEAP_DELTA_ONLY: u8 = 0x20;
/// The `heap_sizes` bit: 4 bytes of extra data follow the row counts.
pub const HEAP_EXTRA_DATA: u8 = 0x40;
/// The `heap_sizes` bit: the metadata can hold rows marked as deleted.
pub const HEAP_HAS_DELETE: u8 = 0x80;

/// The header of the tables stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TablesHeader {
    /// Reserved, zero.
    pub reserved: u32,
    /// The major version of the table schema (2).
    pub major_version: u8,
    /// The minor version of the table schema (0).
    pub minor_version: u8,
    /// The heap size flags (`HEAP_*`).
    pub heap_sizes: u8,
    /// Reserved, one.
    pub reserved2: u8,
    /// The bit mask of the tables that are present.
    pub valid: u64,
    /// The bit mask of the tables that are sorted.
    pub sorted: u64,
    /// The row count of each table, by identifier.
    pub row_counts: [u32; 64],
    /// The extra data that follows the row counts when `heap_sizes` holds
    /// [`HEAP_EXTRA_DATA`].
    pub extra_data: Option<u32>,
}

impl Default for TablesHeader {
    fn default() -> Self {
        Self {
            reserved: 0,
            major_version: 2,
            minor_version: 0,
            heap_sizes: 0,
            reserved2: 1,
            valid: 0,
            sorted: 0,
            row_counts: [0; 64],
            extra_data: None,
        }
    }
}

impl TablesHeader {
    /// Parses the header at the start of the tables stream.
    ///
    /// A bit of the `valid` mask for a table that the schema does not
    /// define has a row count too. The runtime reads that count, skips it
    /// and places no rows (`CoreCLR` `CMiniMdSchema::LoadFrom`); the header
    /// keeps it.
    pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Self> {
        let reserved = cursor.u32()?;
        let major_version = cursor.u8()?;
        let minor_version = cursor.u8()?;
        let heap_sizes = cursor.u8()?;
        let reserved2 = cursor.u8()?;
        let valid = cursor.u64()?;
        let sorted = cursor.u64()?;
        let mut row_counts = [0; 64];
        for (bit, count) in row_counts.iter_mut().enumerate() {
            if valid & (1 << bit) != 0 {
                *count = cursor.u32()?;
            }
        }
        let extra_data = if heap_sizes & HEAP_EXTRA_DATA != 0 {
            Some(cursor.u32()?)
        } else {
            None
        };
        Ok(Self {
            reserved,
            major_version,
            minor_version,
            heap_sizes,
            reserved2,
            valid,
            sorted,
            row_counts,
            extra_data,
        })
    }

    /// Writes the header.
    pub(crate) fn write(&self, out: &mut Vec<u8>) {
        put_u32(out, self.reserved);
        out.extend_from_slice(&[
            self.major_version,
            self.minor_version,
            self.heap_sizes,
            self.reserved2,
        ]);
        put_u64(out, self.valid);
        put_u64(out, self.sorted);
        for (bit, &count) in self.row_counts.iter().enumerate() {
            if self.valid & (1 << bit) != 0 {
                put_u32(out, count);
            }
        }
        if let Some(extra) = self.extra_data {
            put_u32(out, extra);
        }
    }

    /// Returns the row count of a table.
    #[must_use]
    pub const fn row_count(&self, table: TableId) -> u32 {
        self.row_counts[table as usize]
    }

    /// Returns `true` when the `valid` mask holds the table.
    #[must_use]
    pub const fn is_present(&self, table: TableId) -> bool {
        self.valid & (1 << table as u8) != 0
    }

    /// Returns `true` when the `sorted` mask holds the table.
    #[must_use]
    pub const fn is_sorted(&self, table: TableId) -> bool {
        self.sorted & (1 << table as u8) != 0
    }
}

/// The layout of the rows of one table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TableLayout {
    /// The number of rows.
    pub row_count: u32,
    /// The size of a row in bytes.
    pub row_size: u32,
    /// The width of each column in bytes (2 or 4).
    pub widths: [u8; MAX_COLUMNS],
    /// The offset of the first row from the start of the tables stream.
    pub offset: usize,
}

impl TableLayout {
    /// Returns the size of the table in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        self.row_count as usize * self.row_size as usize
    }
}

/// The widths of the indices and the layout of every table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// The width of an index into `#Strings`.
    pub string_width: u8,
    /// The width of an index into `#GUID`.
    pub guid_width: u8,
    /// The width of an index into `#Blob`.
    pub blob_width: u8,
    tables: [TableLayout; 64],
    end: usize,
}

impl Layout {
    /// Computes the layout of the tables that follow a header of
    /// `header_size` bytes.
    ///
    /// `sizing_counts` are the row counts that set the widths of the
    /// indices: the counts of the header, and in a portable PDB also the
    /// counts of the type system tables of the PDB stream. `wide` makes
    /// every index 4 bytes (the `#JTD` marker of a minimal delta).
    #[must_use]
    pub fn compute(
        heap_sizes: u8,
        row_counts: &[u32; 64],
        sizing_counts: &[u32; 64],
        wide: bool,
        header_size: usize,
    ) -> Self {
        let width = |flag: u8| if wide || heap_sizes & flag != 0 { 4 } else { 2 };
        let mut layout = Self {
            string_width: width(HEAP_STRINGS_WIDE),
            guid_width: width(HEAP_GUID_WIDE),
            blob_width: width(HEAP_BLOB_WIDE),
            tables: [TableLayout::default(); 64],
            end: header_size,
        };
        let mut offset = header_size;
        for &table in TableId::ALL {
            let mut entry = TableLayout {
                row_count: row_counts[table as usize],
                offset,
                ..TableLayout::default()
            };
            for (slot, column) in entry.widths.iter_mut().zip(columns(table)) {
                *slot = layout.column_width(column.kind, sizing_counts, wide);
                entry.row_size += u32::from(*slot);
            }
            offset += entry.size();
            layout.tables[table as usize] = entry;
        }
        layout.end = offset;
        layout
    }

    fn column_width(&self, kind: ColumnKind, counts: &[u32; 64], wide: bool) -> u8 {
        let wide_if = |condition: bool| if wide || condition { 4 } else { 2 };
        match kind {
            ColumnKind::U16 => 2,
            ColumnKind::U32 => 4,
            ColumnKind::Strings => self.string_width,
            ColumnKind::Guid => self.guid_width,
            ColumnKind::Blob => self.blob_width,
            ColumnKind::Table(table) => wide_if(counts[table as usize] > 0xFFFF),
            ColumnKind::Coded(coded) => wide_if(coded_is_wide(coded, counts)),
        }
    }

    /// Returns the layout of a table.
    #[must_use]
    pub const fn table(&self, table: TableId) -> &TableLayout {
        &self.tables[table as usize]
    }

    /// Returns the offset of the end of the last table.
    #[must_use]
    pub const fn end(&self) -> usize {
        self.end
    }
}

/// Returns the row counts of the tables that a reader places in the
/// stream. The runtime knows the tables up to `GenericParamConstraint`
/// (0x2C): it places no rows for the other tables, the debug tables of a
/// portable PDB included. A portable PDB (`debug_tables`) has the debug
/// tables (0x30 to 0x37).
pub(crate) fn placed_counts(counts: &[u32; 64], debug_tables: bool) -> [u32; 64] {
    let mut placed = [0; 64];
    for &table in TableId::ALL {
        if debug_tables || (table as u8) < TableId::Document as u8 {
            placed[table as usize] = counts[table as usize];
        }
    }
    placed
}

fn coded_is_wide(kind: CodedIndexKind, counts: &[u32; 64]) -> bool {
    let limit = kind.small_row_limit();
    kind.tables()
        .iter()
        .flatten()
        .any(|&table| counts[table as usize] >= limit)
}

/// Returns an error when the tables of `layout` do not fit `len` bytes.
pub(crate) fn check_fits(layout: &Layout, len: usize) -> Result<()> {
    if layout.end() > len {
        return Err(Error::Truncated {
            structure: "tables stream",
            offset: len,
            needed: layout.end() - len,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn a_header_writes_the_bytes_that_it_parses() {
        let mut header = TablesHeader {
            heap_sizes: HEAP_EXTRA_DATA | HEAP_BLOB_WIDE,
            valid: (1 << 0) | (1 << 2),
            sorted: 0x1600_3301_FA00,
            extra_data: Some(7),
            ..TablesHeader::default()
        };
        header.row_counts[0] = 1;
        header.row_counts[2] = 3;
        let mut out = Vec::new();
        header.write(&mut out);
        assert_eq!(out.len(), 24 + 8 + 4);
        let parsed = TablesHeader::parse(&mut Cursor::new(&out, "test")).unwrap();
        assert_eq!(parsed, header);
        assert!(parsed.is_present(TableId::TypeDef));
        assert!(!parsed.is_present(TableId::TypeRef));
    }

    #[test]
    fn a_header_keeps_the_row_counts_of_tables_that_the_schema_does_not_define() {
        // CoreCLR and .NET Framework load a module whose valid mask has the
        // bits 0x2D, 0x30 and 0x3F; they skip the counts.
        let mut header = TablesHeader {
            valid: (1 << 0x2D) | (1 << 0x30) | (1 << 0x3F) | (1 << 2),
            ..TablesHeader::default()
        };
        header.row_counts[0x2D] = 5;
        header.row_counts[0x30] = 3;
        header.row_counts[0x3F] = 1;
        header.row_counts[2] = 7;
        let mut out = Vec::new();
        header.write(&mut out);
        let parsed = TablesHeader::parse(&mut Cursor::new(&out, "test")).unwrap();
        assert_eq!(parsed, header);
        let placed = placed_counts(&parsed.row_counts, false);
        assert_eq!(
            (placed[2], placed[0x2D], placed[0x30], placed[0x3F]),
            (7, 0, 0, 0)
        );
        assert_eq!(placed_counts(&parsed.row_counts, true)[0x30], 3);
    }

    #[test]
    fn the_widths_follow_the_row_counts() {
        let mut counts = [0; 64];
        counts[TableId::TypeDef as usize] = 0x4000;
        let layout = Layout::compute(HEAP_STRINGS_WIDE, &counts, &counts, false, 24);
        let type_ref = layout.table(TableId::TypeRef);
        // ResolutionScope (2), strings (4 + 4).
        assert_eq!(type_ref.row_size, 10);
        // Flags (4), strings (4 + 4), TypeDefOrRef (4: 0x4000 rows), Field (2), MethodDef (2).
        assert_eq!(layout.table(TableId::TypeDef).row_size, 20);
        assert_eq!(layout.table(TableId::InterfaceImpl).row_size, 6);
        let all_wide = Layout::compute(0, &counts, &counts, true, 24);
        assert_eq!(all_wide.table(TableId::Field).row_size, 10);
        assert_eq!(layout.end(), 24 + 0x4000 * 20);
    }
}
