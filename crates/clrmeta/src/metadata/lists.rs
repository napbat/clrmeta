//! The runs of rows that list columns own: the fields and methods of a
//! type, the parameters of a method, the events and properties of a type.

use core::marker::PhantomData;

use crate::error::Result;
use crate::metadata::Metadata;
use crate::tables::{
    EventMapRow, EventRow, FieldRow, ListColumn, LocalConstantRow, LocalScopeRow, LocalVariableRow,
    MethodDefRow, ParamRow, PropertyMapRow, PropertyRow, RawTable, TableId, TableRow, TypeDefRow,
    list_columns,
};
use crate::token::Rid;

/// The rows of a run, through the `Ptr` table when it has rows.
#[derive(Debug, Clone)]
pub struct RowList<'a, R> {
    indirection: Option<RawTable<'a>>,
    next: u32,
    end: u32,
    rows: PhantomData<fn() -> R>,
}

impl<R> RowList<'_, R> {
    fn empty() -> Self {
        Self {
            indirection: None,
            next: 0,
            end: 0,
            rows: PhantomData,
        }
    }
}

impl<R> Iterator for RowList<'_, R> {
    type Item = Rid<R>;

    fn next(&mut self) -> Option<Rid<R>> {
        if self.next >= self.end {
            return None;
        }
        let position = self.next;
        self.next += 1;
        Some(Rid::new(match &self.indirection {
            Some(ptr) => ptr.raw_in_range(position)[0],
            None => position,
        }))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.end.saturating_sub(self.next) as usize;
        (left, Some(left))
    }
}

impl<R> ExactSizeIterator for RowList<'_, R> {}

impl<'a> Metadata<'a> {
    /// Returns the run of rows that the list column `list` of row `row` of
    /// `owner` owns.
    ///
    /// The run ends where the run of the next row starts, or at the end of
    /// the target table for the last row. The read-write reader of the
    /// runtime (metadata with a `#-` or a `#Schema` stream) reads a next
    /// start of 0 as the end of the table (`CoreCLR`
    /// `CMiniMdRW::Impl_GetEndRidForColumn`). The runtime rejects a run that
    /// ends before it starts and fails on a row outside the table; this
    /// reader reads such a run as empty and cuts a run at the end of the
    /// table, and the validator reports both. A run that starts at row 0 is
    /// empty.
    fn run<R: TableRow>(
        &self,
        owner: TableId,
        row: u32,
        list: ListColumn,
    ) -> Result<RowList<'a, R>> {
        let owners = self.tables().raw_table(owner);
        let start = owners.raw(row)?[list.column];
        let indirection = list
            .indirection
            .map(|ptr| self.tables().raw_table(ptr))
            .filter(|ptr| !ptr.is_empty());
        let limit = indirection
            .map_or_else(|| self.tables().row_count(list.target), |ptr| ptr.len())
            .saturating_add(1);
        if start == 0 {
            return Ok(RowList::empty());
        }
        let end = if row < owners.len() {
            match owners.raw_in_range(row + 1)[list.column] {
                0 if self.stream_selection().uncompressed => limit,
                next => next,
            }
        } else {
            limit
        };
        let start = start.min(limit);
        Ok(RowList {
            indirection,
            next: start,
            end: end.clamp(start, limit),
            rows: PhantomData,
        })
    }

    /// Returns the fields of a type.
    ///
    /// # Errors
    ///
    /// Returns an error when the type is outside the `TypeDef` table.
    pub fn fields_of(&self, ty: Rid<TypeDefRow>) -> Result<RowList<'a, FieldRow>> {
        self.run(
            TableId::TypeDef,
            ty.row(),
            list_columns(TableId::TypeDef)[0],
        )
    }

    /// Returns the methods of a type.
    ///
    /// # Errors
    ///
    /// Returns an error when the type is outside the `TypeDef` table.
    pub fn methods_of(&self, ty: Rid<TypeDefRow>) -> Result<RowList<'a, MethodDefRow>> {
        self.run(
            TableId::TypeDef,
            ty.row(),
            list_columns(TableId::TypeDef)[1],
        )
    }

    /// Returns the parameter rows of a method. A method can have fewer rows
    /// than parameters: a row exists only for a named or attributed
    /// parameter. [`ParamRow::sequence`] gives the position.
    ///
    /// # Errors
    ///
    /// Returns an error when the method is outside the `MethodDef` table.
    pub fn params_of(&self, method: Rid<MethodDefRow>) -> Result<RowList<'a, ParamRow>> {
        self.run(
            TableId::MethodDef,
            method.row(),
            list_columns(TableId::MethodDef)[0],
        )
    }

    /// Returns the events of a type.
    ///
    /// # Errors
    ///
    /// Returns an error when the `EventMap` row of the type is not valid.
    pub fn events_of(&self, ty: Rid<TypeDefRow>) -> Result<RowList<'a, EventRow>> {
        let map = self.tables().table::<EventMapRow>();
        match map.rows_with_key(0, ty.row()).next() {
            Some(row) => self.run(
                TableId::EventMap,
                row.row(),
                list_columns(TableId::EventMap)[0],
            ),
            None => Ok(RowList::empty()),
        }
    }

    /// Returns the properties of a type.
    ///
    /// # Errors
    ///
    /// Returns an error when the `PropertyMap` row of the type is not valid.
    pub fn properties_of(&self, ty: Rid<TypeDefRow>) -> Result<RowList<'a, PropertyRow>> {
        let map = self.tables().table::<PropertyMapRow>();
        match map.rows_with_key(0, ty.row()).next() {
            Some(row) => self.run(
                TableId::PropertyMap,
                row.row(),
                list_columns(TableId::PropertyMap)[0],
            ),
            None => Ok(RowList::empty()),
        }
    }

    /// Returns the local variables of a scope of a portable PDB.
    ///
    /// # Errors
    ///
    /// Returns an error when the scope is outside the `LocalScope` table.
    pub fn local_variables_of(
        &self,
        scope: Rid<LocalScopeRow>,
    ) -> Result<RowList<'a, LocalVariableRow>> {
        self.run(
            TableId::LocalScope,
            scope.row(),
            list_columns(TableId::LocalScope)[0],
        )
    }

    /// Returns the local constants of a scope of a portable PDB.
    ///
    /// # Errors
    ///
    /// Returns an error when the scope is outside the `LocalScope` table.
    pub fn local_constants_of(
        &self,
        scope: Rid<LocalScopeRow>,
    ) -> Result<RowList<'a, LocalConstantRow>> {
        self.run(
            TableId::LocalScope,
            scope.row(),
            list_columns(TableId::LocalScope)[1],
        )
    }

    /// Returns the owner of a member of a list: the last row of `owner`
    /// whose run starts at or before the member.
    pub(crate) fn list_owner(&self, owner: TableId, list: ListColumn, member: u32) -> Option<u32> {
        let position = match list.indirection.map(|ptr| self.tables().raw_table(ptr)) {
            Some(ptr) if !ptr.is_empty() => {
                (1..=ptr.len()).find(|&p| ptr.raw_in_range(p)[0] == member)?
            }
            _ => member,
        };
        let owners = self.tables().raw_table(owner);
        let (mut low, mut high) = (0, owners.len());
        while low < high {
            let mid = low + (high - low) / 2;
            if owners.raw_in_range(mid + 1)[list.column] <= position {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        (low > 0).then_some(low)
    }
}
