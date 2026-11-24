//! The `#Pdb` stream of a portable PDB.

use alloc::vec::Vec;

use crate::bytes::{Cursor, put_u32, put_u64};
use crate::error::Result;
use crate::tables::TableId;
use crate::token::Token;

/// The `#Pdb` stream: the identity of the PDB, the entry point, and the row
/// counts of the type system tables of the module that the PDB describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbStream {
    /// The PDB identifier: a GUID and a stamp.
    pub id: [u8; 20],
    /// The entry point `MethodDef` token, or a null token.
    pub entry_point: Token,
    /// The bit mask of the type system tables that the PDB refers to.
    pub referenced_type_system_tables: u64,
    /// The row count of each referenced table, by identifier.
    pub type_system_table_rows: [u32; 64],
}

impl PdbStream {
    /// Parses the stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the stream is cut short.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data, "#Pdb");
        let id = cursor.array::<20>()?;
        let entry_point = Token(cursor.u32()?);
        let referenced_type_system_tables = cursor.u64()?;
        let mut type_system_table_rows = [0; 64];
        for (bit, count) in type_system_table_rows.iter_mut().enumerate() {
            if referenced_type_system_tables & (1 << bit) != 0 {
                *count = cursor.u32()?;
            }
        }
        Ok(Self {
            id,
            entry_point,
            referenced_type_system_tables,
            type_system_table_rows,
        })
    }

    /// Writes the stream.
    #[must_use]
    pub fn write(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.id);
        put_u32(&mut out, self.entry_point.0);
        put_u64(&mut out, self.referenced_type_system_tables);
        for (bit, &count) in self.type_system_table_rows.iter().enumerate() {
            if self.referenced_type_system_tables & (1 << bit) != 0 {
                put_u32(&mut out, count);
            }
        }
        out
    }

    /// Returns the row count of a referenced type system table.
    #[must_use]
    pub const fn row_count(&self, table: TableId) -> u32 {
        self.type_system_table_rows[table as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pdb_stream_writes_the_bytes_that_it_parses() {
        let mut stream = PdbStream {
            id: [7; 20],
            entry_point: Token::new(TableId::MethodDef, 3),
            referenced_type_system_tables: (1 << 2) | (1 << 6),
            type_system_table_rows: [0; 64],
        };
        stream.type_system_table_rows[2] = 10;
        stream.type_system_table_rows[6] = 70_000;
        let bytes = stream.write();
        assert_eq!(bytes.len(), 20 + 4 + 8 + 8);
        let parsed = PdbStream::parse(&bytes).unwrap();
        assert_eq!(parsed, stream);
        assert_eq!(parsed.row_count(TableId::MethodDef), 70_000);
        assert!(PdbStream::parse(&bytes[..30]).is_err());
    }
}
