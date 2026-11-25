//! The additions of rows to the metadata of a builder: references to types,
//! members and assemblies, signatures, and new methods of a type.
//!
//! Each `add_*` method of a table without a sort order reuses a row that is
//! equal to the new row, and appends the row otherwise, so the tokens of the
//! existing rows stay valid. A new method is different: the methods of one
//! type are a run of the `MethodDef` table (II.22.37), so the new row goes
//! to the end of the run of its type. Without a `MethodPtr` table, the rows
//! after it get the next number; the builder writes the new number into
//! every column that names one of them, and [`MethodRenumbering`] gives the
//! new token of each old token for the bytes outside the tables (the code of
//! the method bodies, the entry point of the CLI header). A renumbering
//! keeps the order of the rows, so each sorted table stays sorted.

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::heaps::{BlobHeap, BlobIndex, StringIndex, StringsHeap};
use crate::tables::{
    AnyRow, AssemblyRefRow, CodedIndexKind, ColumnKind, MemberRefRow, MethodDefRow, MethodPtrRow,
    MethodSpecRow, ParamPtrRow, ParamRow, StandAloneSigRow, TableId, TypeRefRow, TypeSpecRow,
    columns,
};
use crate::token::{Rid, Token};
use crate::write::MetadataBuilder;

/// The new numbers of the `MethodDef` rows after the additions and the
/// removals of methods ([`MetadataBuilder::add_method`],
/// [`MetadataBuilder::remove_method`]), and of the `MethodSpec` rows after
/// the removal of the instantiations of a removed method.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MethodRenumbering {
    /// The number of `MethodDef` rows before the first change.
    original: u32,
    /// Each change of a table, in order, in the numbering that holds when
    /// it applies.
    changes: Vec<(TableId, RowChange)>,
}

/// One change of a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowChange {
    /// A new row: the rows from it on move up by one.
    Insert(u32),
    /// A removed row: the rows after it move down by one.
    Remove(u32),
}

impl MethodRenumbering {
    /// Returns `true` when no method or instantiation that existed before
    /// the changes has a new number and none went.
    #[must_use]
    pub fn is_identity(&self) -> bool {
        self.changes.is_empty()
            || (!self
                .changes
                .iter()
                .any(|(_, change)| matches!(change, RowChange::Remove(_)))
                && self
                    .token(Token::new(TableId::MethodDef, self.original))
                    .row()
                    == self.original)
    }

    /// Returns the token of the method or the instantiation (`MethodSpec`)
    /// that `token` named before the changes, or the null token of its
    /// table for a row that went. A token of another table stays the same.
    #[must_use]
    pub fn token(&self, token: Token) -> Token {
        let Some(table) = token
            .table()
            .filter(|table| matches!(table, TableId::MethodDef | TableId::MethodSpec))
        else {
            return token;
        };
        if token.is_null() {
            return token;
        }
        self.changes
            .iter()
            .filter(|(changed, _)| *changed == table)
            .try_fold(token.row(), |row, &(_, change)| step(row, change))
            .map_or(Token::new(table, 0), |row| Token::new(table, row))
    }

    /// Tells whether the method or the instantiation that `token` named
    /// before the changes went.
    #[must_use]
    pub fn is_removed(&self, token: Token) -> bool {
        matches!(
            token.table(),
            Some(TableId::MethodDef | TableId::MethodSpec)
        ) && !token.is_null()
            && self.token(token).is_null()
    }

    /// Returns the token of each added method in the current numbering, in
    /// the order of the additions.
    pub fn added(&self) -> impl Iterator<Item = Token> + '_ {
        self.changes
            .iter()
            .enumerate()
            .filter_map(|(at, change)| match *change {
                (TableId::MethodDef, RowChange::Insert(row)) => Some((at, row)),
                _ => None,
            })
            .filter_map(|(at, row)| {
                self.changes[at + 1..]
                    .iter()
                    .filter(|(table, _)| *table == TableId::MethodDef)
                    .try_fold(row, |row, &(_, change)| step(row, change))
            })
            .map(|row| Token::new(TableId::MethodDef, row))
    }

    /// Records a new `MethodDef` row `row` of a table that held `count`
    /// rows before it: the rows from `row` on move up by one.
    fn insert(&mut self, row: u32, count: u32) {
        self.first_change(count);
        self.changes
            .push((TableId::MethodDef, RowChange::Insert(row)));
    }

    /// Records the removal of the row `row` of `table`, which held `count`
    /// rows before it when it is the `MethodDef` table: the rows after
    /// `row` move down by one.
    fn remove(&mut self, table: TableId, row: u32, count: u32) {
        if table == TableId::MethodDef {
            self.first_change(count);
        }
        self.changes.push((table, RowChange::Remove(row)));
    }

    /// Records the number of `MethodDef` rows before the first change of
    /// the table.
    fn first_change(&mut self, count: u32) {
        if !self
            .changes
            .iter()
            .any(|(table, _)| *table == TableId::MethodDef)
        {
            self.original = count;
        }
    }
}

/// The rows that go with a removed method, each list from the last row on.
struct OwnedRows {
    /// The `MethodSpec` rows that instantiate the method.
    specs: Vec<u32>,
    /// The `GenericParam` rows of the method.
    parameters: Vec<u32>,
    /// The `GenericParamConstraint` rows of these generic parameters.
    constraints: Vec<u32>,
}

/// One column of a row that names a row of another table
/// ([`MetadataBuilder::references`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowReference {
    /// The table of the row that holds the column.
    pub table: TableId,
    /// The 1-based number of the row that holds the column.
    pub row: u32,
    /// The name of the column in ECMA-335, in snake case, such as
    /// `attribute_type` of `CustomAttribute`.
    pub column: &'static str,
    /// The 1-based number of the row that the column names.
    pub target: u32,
}

/// Returns the number of `row` after `change`, or `None` for the row that
/// `change` removes.
fn step(row: u32, change: RowChange) -> Option<u32> {
    match change {
        RowChange::Insert(at) if row >= at => Some(row + 1),
        RowChange::Remove(at) if row == at => None,
        RowChange::Remove(at) if row > at => Some(row - 1),
        RowChange::Insert(_) | RowChange::Remove(_) => Some(row),
    }
}

impl MetadataBuilder {
    /// Returns the string at `index` of the `#Strings` heap, or `None` when
    /// the index is not valid.
    fn string(&self, index: StringIndex) -> Option<&[u8]> {
        StringsHeap::new(self.strings.as_bytes())
            .get_bytes(index)
            .ok()
    }

    /// Returns the blob at `index` of the `#Blob` heap, or `None` when the
    /// index is not valid.
    fn blob(&self, index: BlobIndex) -> Option<&[u8]> {
        BlobHeap::new(self.blobs.as_bytes()).get(index).ok()
    }

    /// Returns `true` when `index` names the string `value`.
    fn is_string(&self, index: StringIndex, value: &str) -> bool {
        self.string(index) == Some(value.as_bytes())
    }

    /// Returns `true` when `index` names the blob `value`.
    fn is_blob(&self, index: BlobIndex, value: &[u8]) -> bool {
        self.blob(index) == Some(value)
    }

    /// Adds a reference to another assembly (`AssemblyRef`, II.22.5) and
    /// returns its token. A row with the same name and culture is reused,
    /// whatever version it states, because a module references each
    /// assembly one time.
    ///
    /// # Errors
    ///
    /// Returns an error when a heap or the table is full.
    pub fn add_assembly_ref(
        &mut self,
        name: &str,
        version: [u16; 4],
        public_key_or_token: &[u8],
        culture: &str,
    ) -> Result<Token> {
        let found =
            self.rows.assembly_ref.iter().position(|row| {
                self.is_string(row.name, name) && self.is_string(row.culture, culture)
            });
        if let Some(position) = found {
            return row_token(TableId::AssemblyRef, position);
        }
        let row = AssemblyRefRow {
            major_version: version[0],
            minor_version: version[1],
            build_number: version[2],
            revision_number: version[3],
            // A full public key sets the flag `PublicKey` (II.23.1.2); a
            // token of 8 bytes does not.
            flags: u32::from(public_key_or_token.len() > 8),
            public_key_or_token: self.blobs.add(public_key_or_token)?,
            name: self.strings.add(name)?,
            culture: self.strings.add(culture)?,
            hash_value: BlobIndex(0),
        };
        self.rows.assembly_ref.push(row);
        row_token(TableId::AssemblyRef, self.rows.assembly_ref.len() - 1)
    }

    /// Adds a reference to a type (`TypeRef`, II.22.38) and returns its
    /// token. An equal row is reused.
    ///
    /// # Errors
    ///
    /// Returns an error when `scope` is not a `Module`, `ModuleRef`,
    /// `AssemblyRef` or `TypeRef` token, or a heap or the table is full.
    pub fn add_type_ref(&mut self, scope: Token, namespace: &str, name: &str) -> Result<Token> {
        coded(CodedIndexKind::ResolutionScope, scope)?;
        let found = self.rows.type_ref.iter().position(|row| {
            row.resolution_scope == scope
                && self.is_string(row.type_name, name)
                && self.is_string(row.type_namespace, namespace)
        });
        if let Some(position) = found {
            return row_token(TableId::TypeRef, position);
        }
        let row = TypeRefRow {
            resolution_scope: scope,
            type_name: self.strings.add(name)?,
            type_namespace: self.strings.add(namespace)?,
        };
        self.rows.type_ref.push(row);
        row_token(TableId::TypeRef, self.rows.type_ref.len() - 1)
    }

    /// Adds a type specification (`TypeSpec`, II.22.39) with the blob of
    /// its type (II.23.2.14) and returns its token. An equal row is reused.
    ///
    /// # Errors
    ///
    /// Returns an error when a heap or the table is full.
    pub fn add_type_spec(&mut self, signature: &[u8]) -> Result<Token> {
        let found =
            (self.rows.type_spec.iter()).position(|row| self.is_blob(row.signature, signature));
        if let Some(position) = found {
            return row_token(TableId::TypeSpec, position);
        }
        let signature = self.blobs.add(signature)?;
        self.rows.type_spec.push(TypeSpecRow { signature });
        row_token(TableId::TypeSpec, self.rows.type_spec.len() - 1)
    }

    /// Adds a reference to a member (`MemberRef`, II.22.25) and returns its
    /// token. An equal row is reused.
    ///
    /// # Errors
    ///
    /// Returns an error when `parent` is not a `TypeDef`, `TypeRef`,
    /// `ModuleRef`, `MethodDef` or `TypeSpec` token, or a heap or the table
    /// is full.
    pub fn add_member_ref(&mut self, parent: Token, name: &str, signature: &[u8]) -> Result<Token> {
        coded(CodedIndexKind::MemberRefParent, parent)?;
        let found = self.rows.member_ref.iter().position(|row| {
            row.class == parent
                && self.is_string(row.name, name)
                && self.is_blob(row.signature, signature)
        });
        if let Some(position) = found {
            return row_token(TableId::MemberRef, position);
        }
        let row = MemberRefRow {
            class: parent,
            name: self.strings.add(name)?,
            signature: self.blobs.add(signature)?,
        };
        self.rows.member_ref.push(row);
        row_token(TableId::MemberRef, self.rows.member_ref.len() - 1)
    }

    /// Adds an instantiation of a generic method (`MethodSpec`, II.22.29)
    /// with the blob of its type arguments (II.23.2.15) and returns its
    /// token. An equal row is reused.
    ///
    /// # Errors
    ///
    /// Returns an error when `method` is not a `MethodDef` or `MemberRef`
    /// token, or a heap or the table is full.
    pub fn add_method_spec(&mut self, method: Token, instantiation: &[u8]) -> Result<Token> {
        coded(CodedIndexKind::MethodDefOrRef, method)?;
        let found =
            self.rows.method_spec.iter().position(|row| {
                row.method == method && self.is_blob(row.instantiation, instantiation)
            });
        if let Some(position) = found {
            return row_token(TableId::MethodSpec, position);
        }
        let instantiation = self.blobs.add(instantiation)?;
        self.rows.method_spec.push(MethodSpecRow {
            method,
            instantiation,
        });
        row_token(TableId::MethodSpec, self.rows.method_spec.len() - 1)
    }

    /// Adds a stand-alone signature (`StandAloneSig`, II.22.36), such as the
    /// local variables of a method body, and returns its token. An equal row
    /// is reused.
    ///
    /// # Errors
    ///
    /// Returns an error when a heap or the table is full.
    pub fn add_stand_alone_sig(&mut self, signature: &[u8]) -> Result<Token> {
        let found = (self.rows.stand_alone_sig.iter())
            .position(|row| self.is_blob(row.signature, signature));
        if let Some(position) = found {
            return row_token(TableId::StandAloneSig, position);
        }
        let signature = self.blobs.add(signature)?;
        self.rows
            .stand_alone_sig
            .push(StandAloneSigRow { signature });
        row_token(TableId::StandAloneSig, self.rows.stand_alone_sig.len() - 1)
    }

    /// Sets the signature of the method `method` to the blob `signature`
    /// (II.23.2.1).
    ///
    /// # Errors
    ///
    /// Returns an error when `method` names no `MethodDef` row, or the heap
    /// is full.
    pub fn set_method_signature(&mut self, method: Token, signature: &[u8]) -> Result<()> {
        let index = self.method_position(method)?;
        self.rows.method_def[index].signature = self.blobs.add(signature)?;
        Ok(())
    }

    /// Returns the 0-based position of the `MethodDef` row of `token`.
    fn method_position(&self, token: Token) -> Result<usize> {
        let count = self.rows.method_def.len();
        Rid::<MethodDefRow>::from_token(token)
            .and_then(|rid| usize::try_from(rid.row()).ok())
            .and_then(|row| row.checked_sub(1))
            .filter(|&index| index < count)
            .ok_or(Error::Token {
                token,
                reason: "the token names no MethodDef row",
            })
    }

    /// Adds the method `row` with one `Param` row for each name of
    /// `parameters` (sequence 1, 2, …) to the end of the methods of the type
    /// `owner`, and returns its token.
    ///
    /// With a `MethodPtr` table (unoptimized metadata), the new row is the
    /// last `MethodDef` row and a new `MethodPtr` row names it, so no method
    /// gets a new number. Without one, the new row goes after the last
    /// method of `owner`: each row after it gets the next number, each
    /// column that names one of them gets the new number (the debug tables
    /// of a portable PDB and the tokens of the edit-and-continue tables
    /// included), and `renumbering` records the change. A
    /// `MethodDebugInformation` table, which follows the `MethodDef` table
    /// row by row (portable PDB), gets an empty row for the new method. The
    /// `Param` rows go to the start of the parameters of the method after
    /// the new one in the same way, and the later `Param` rows get new
    /// numbers; no instruction names a `Param` row.
    ///
    /// # Errors
    ///
    /// Returns an error when `owner` names no `TypeDef` row, when the method
    /// runs of the types are not in ascending order, when a heap or a table
    /// is full, or when a renumbered row no longer fits its column.
    pub fn add_method(
        &mut self,
        owner: Token,
        mut row: MethodDefRow,
        parameters: &[&str],
        renumbering: &mut MethodRenumbering,
    ) -> Result<Token> {
        let refuse = |reason| Error::Token {
            token: owner,
            reason,
        };
        let types = &self.rows.type_def;
        let position = Rid::<crate::tables::TypeDefRow>::from_token(owner)
            .and_then(|rid| usize::try_from(rid.row()).ok())
            .and_then(|row| row.checked_sub(1))
            .filter(|&index| index < types.len())
            .ok_or(refuse("the token names no TypeDef row"))?;
        let indirect = !self.rows.method_ptr.is_empty();
        let list_count = if indirect {
            self.rows.method_ptr.len()
        } else {
            self.rows.method_def.len()
        };
        let start = types[position].method_list.row();
        let end = types
            .get(position + 1)
            .map_or_else(|| to_row(list_count + 1), |next| Ok(next.method_list.row()))?;
        if start > end || end as usize > list_count + 1 {
            return Err(refuse("the method runs of the types are not in order"));
        }
        let param_end = to_row(if self.rows.param_ptr.is_empty() {
            self.rows.param.len() + 1
        } else {
            self.rows.param_ptr.len() + 1
        })?;
        if indirect {
            // The new method is the last row; its parameters are the run at
            // the end of the Param table.
            let methods = self.rows.method_def.len();
            self.insert_params(param_end, parameters, methods)?;
            row.param_list = Rid::new(param_end);
            let count = to_row(methods)?;
            self.rows.method_def.push(row);
            let method = count + 1;
            if !self.rows.method_debug_information.is_empty() {
                self.rows
                    .method_debug_information
                    .push(crate::tables::MethodDebugInformationRow::default());
            }
            self.rows.method_ptr.insert(
                end as usize - 1,
                MethodPtrRow {
                    method: Rid::new(method),
                },
            );
            for later in &mut self.rows.type_def[position + 1..] {
                if later.method_list.row() >= end {
                    later.method_list = Rid::new(later.method_list.row() + 1);
                }
            }
            renumbering.insert(method, count);
            self.count_pdb_method(|row| row);
            return Ok(Token::new(TableId::MethodDef, method));
        }
        // The parameters of the new method start where the parameters of
        // the method after it start.
        let at = self
            .rows
            .method_def
            .get(end as usize - 1)
            .map_or(param_end, |next| next.param_list.row());
        self.insert_params(at, parameters, end as usize - 1)?;
        row.param_list = Rid::new(at);
        let shift = |row: u32| if row >= end { row + 1 } else { row };
        // A type before the new method keeps its run, also when its run is
        // empty and starts where the new method goes.
        self.remap_references(TableId::MethodDef, shift, |table, index| {
            table == TableId::TypeDef && index <= position
        })?;
        let count = to_row(self.rows.method_def.len())?;
        self.rows.method_def.insert(end as usize - 1, row);
        if !self.rows.method_debug_information.is_empty() {
            self.remap_references(TableId::MethodDebugInformation, shift, |_, _| false)?;
            let index = (end as usize - 1).min(self.rows.method_debug_information.len());
            self.rows
                .method_debug_information
                .insert(index, crate::tables::MethodDebugInformationRow::default());
        }
        renumbering.insert(end, count);
        self.count_pdb_method(shift);
        self.sort_tables()?;
        Ok(Token::new(TableId::MethodDef, end))
    }

    /// Removes the method `method`, with its `Param` rows, its row of a
    /// `MethodDebugInformation` table, its instantiations (`MethodSpec`),
    /// its generic parameters and their constraints, and gives each later
    /// row of these tables the number before it in every column that names
    /// one, the debug tables and the tokens of the edit-and-continue tables
    /// included. `renumbering` records the new numbers of the methods and
    /// of the instantiations, so the caller writes the new tokens into the
    /// bytes outside the tables, such as the code of the method bodies. The
    /// caller checks that no code names the method or an instantiation of
    /// it.
    ///
    /// # Errors
    ///
    /// Returns an error, and changes nothing, when `method` names no
    /// `MethodDef` row, when the metadata has a `MethodPtr` or a `ParamPtr`
    /// table (unoptimized metadata), when a row of another table names the
    /// method, one of its parameters, instantiations, generic parameters or
    /// constraints (such as a custom attribute), or when the program
    /// database names it as its entry point. It returns an error after a
    /// partial change only when a renumbered row no longer fits its column.
    pub fn remove_method(
        &mut self,
        method: Token,
        renumbering: &mut MethodRenumbering,
    ) -> Result<()> {
        let refuse = |reason| Error::Token {
            token: method,
            reason,
        };
        if !self.rows.method_ptr.is_empty() || !self.rows.param_ptr.is_empty() {
            return Err(refuse("the metadata has a MethodPtr or a ParamPtr table"));
        }
        let count = to_row(self.rows.method_def.len())?;
        let row = Some(method)
            .filter(|token| token.table() == Some(TableId::MethodDef))
            .map(Token::row)
            .filter(|&row| (1..=count).contains(&row))
            .ok_or(refuse("the token names no MethodDef row"))?;
        if self
            .pdb
            .as_ref()
            .is_some_and(|pdb| pdb.entry_point == method)
        {
            return Err(refuse(
                "the program database names the method as its entry point",
            ));
        }
        let owned = self.owned_rows(method);
        // The run of a type names its first method, and the instantiations
        // and the generic parameters of the method go with it; no other
        // column may name the method.
        if self.names_row(TableId::MethodDef, row..row + 1, |table| {
            matches!(
                table,
                TableId::TypeDef | TableId::MethodSpec | TableId::GenericParam
            )
        })? {
            return Err(refuse("a row of the tables still names the method"));
        }
        // A custom attribute of an instantiation, a generic parameter or a
        // constraint stays, so it refuses the removal. A constraint names
        // the generic parameter that goes with it.
        for (table, rows, skip) in [
            (TableId::MethodSpec, &owned.specs, None),
            (
                TableId::GenericParam,
                &owned.parameters,
                Some(TableId::GenericParamConstraint),
            ),
            (TableId::GenericParamConstraint, &owned.constraints, None),
        ] {
            for &owned_row in rows {
                if self.names_row(table, owned_row..owned_row + 1, |named| Some(named) == skip)? {
                    return Err(refuse(
                        "a row of the tables names an instantiation or a generic parameter of the method",
                    ));
                }
            }
        }
        let first = self.rows.method_def[row as usize - 1].param_list.row();
        let end = self
            .rows
            .method_def
            .get(row as usize)
            .map_or(to_row(self.rows.param.len() + 1)?, |next| {
                next.param_list.row()
            });
        // The run of a method names its first parameter; no other column
        // may name a parameter of the method.
        if end > first
            && self.names_row(TableId::Param, first..end, |table| {
                table == TableId::MethodDef
            })?
        {
            return Err(refuse(
                "a row of the tables names a parameter of the method",
            ));
        }
        // Every check passed: the removals start. The rows of each table go
        // from the last one on, so the numbers of the next ones stay.
        for &spec in &owned.specs {
            self.remove_row(TableId::MethodSpec, spec)?;
            renumbering.remove(TableId::MethodSpec, spec, 0);
        }
        for &constraint in &owned.constraints {
            self.remove_row(TableId::GenericParamConstraint, constraint)?;
        }
        for &parameter in &owned.parameters {
            self.remove_row(TableId::GenericParam, parameter)?;
        }
        if end > first {
            let removed = end - first;
            self.remap_references(
                TableId::Param,
                |param| if param >= end { param - removed } else { param },
                |_, _| false,
            )?;
            self.rows.param.drain(first as usize - 1..end as usize - 1);
        }
        let shift = |later: u32| if later > row { later - 1 } else { later };
        self.remap_references(TableId::MethodDef, shift, |_, _| false)?;
        self.rows.method_def.remove(row as usize - 1);
        if !self.rows.method_debug_information.is_empty() {
            self.remap_references(TableId::MethodDebugInformation, shift, |_, _| false)?;
            if (row as usize) <= self.rows.method_debug_information.len() {
                self.rows.method_debug_information.remove(row as usize - 1);
            }
        }
        renumbering.remove(TableId::MethodDef, row, count);
        self.count_pdb_method(shift);
        self.sort_tables()
    }

    /// Returns the rows that go with `method`: its instantiations, its
    /// generic parameters and their constraints, each list from the last
    /// row on.
    fn owned_rows(&self, method: Token) -> OwnedRows {
        let rows = |held: Vec<bool>| -> Vec<u32> {
            (held.iter().enumerate())
                .filter(|(_, held)| **held)
                .filter_map(|(at, _)| to_row(at + 1).ok())
                .rev()
                .collect()
        };
        let parameters = rows(
            (self.rows.generic_param.iter())
                .map(|parameter| parameter.owner == method)
                .collect(),
        );
        OwnedRows {
            specs: rows(
                (self.rows.method_spec.iter())
                    .map(|spec| spec.method == method)
                    .collect(),
            ),
            constraints: rows(
                (self.rows.generic_param_constraint.iter())
                    .map(|constraint| parameters.contains(&constraint.owner.row()))
                    .collect(),
            ),
            parameters,
        }
    }

    /// Removes the row `row` of `table`, a table that no run names, and
    /// gives the later rows the number before them in every column. The
    /// caller checks that no column names the row.
    fn remove_row(&mut self, table: TableId, row: u32) -> Result<()> {
        self.remap_references(
            table,
            |later| if later > row { later - 1 } else { later },
            |_, _| false,
        )?;
        let at = row as usize - 1;
        match table {
            TableId::MethodSpec => {
                self.rows.method_spec.remove(at);
            }
            TableId::GenericParam => {
                self.rows.generic_param.remove(at);
            }
            TableId::GenericParamConstraint => {
                self.rows.generic_param_constraint.remove(at);
            }
            _ => unreachable!("only the rows that go with a method are removed"),
        }
        Ok(())
    }

    /// Tells whether a column of a table that `skip` does not name holds a
    /// row of `target` in `rows`.
    fn names_row(
        &mut self,
        target: TableId,
        rows: core::ops::Range<u32>,
        skip: impl Fn(TableId) -> bool,
    ) -> Result<bool> {
        let named = core::cell::Cell::new(false);
        self.remap_references(
            target,
            |row| {
                if rows.contains(&row) {
                    named.set(true);
                }
                row
            },
            |table, _| skip(table),
        )?;
        Ok(named.get())
    }

    /// Counts the new method in the `#Pdb` stream, which states the row
    /// count of the `MethodDef` table that it refers to, and gives its entry
    /// point the new number.
    fn count_pdb_method(&mut self, shift: impl Fn(u32) -> u32) {
        let count = u32::try_from(self.rows.method_def.len()).unwrap_or(u32::MAX);
        if let Some(pdb) = &mut self.pdb {
            let methods = &mut pdb.type_system_table_rows[TableId::MethodDef as usize];
            if *methods != 0 {
                *methods = count;
            }
            let entry = pdb.entry_point;
            if entry.table() == Some(TableId::MethodDef) && !entry.is_null() {
                pdb.entry_point = Token::new(TableId::MethodDef, shift(entry.row()));
            }
        }
    }

    /// Inserts one `Param` row for each name of `names` at the row `at` of
    /// the parameter list (the `ParamPtr` table when it exists), and gives
    /// the later rows of the list the next numbers in every column that
    /// names them. The `param_list` of the `MethodDef` rows before the
    /// 0-based `first_later` stays: their runs end where the new run starts.
    fn insert_params(&mut self, at: u32, names: &[&str], first_later: usize) -> Result<()> {
        if names.is_empty() {
            return Ok(());
        }
        let count = to_row(names.len())?;
        let mut rows = Vec::with_capacity(names.len());
        for (index, name) in names.iter().enumerate() {
            rows.push(ParamRow {
                flags: 0,
                sequence: u16::try_from(index + 1).map_err(|_| Error::Overflow {
                    structure: "Param",
                    value: index as u64 + 1,
                })?,
                name: self.strings.add(name)?,
            });
        }
        let shift = |row: u32| if row >= at { row + count } else { row };
        let keep = |table, index| table == TableId::MethodDef && index < first_later;
        let slot = at as usize - 1;
        if self.rows.param_ptr.is_empty() {
            self.remap_references(TableId::Param, shift, keep)?;
            self.rows.param.splice(slot..slot, rows);
        } else {
            // The new Param rows go to the end of their table; the new
            // ParamPtr rows name them in the list of the method.
            let first = to_row(self.rows.param.len() + 1)?;
            self.rows.param.extend(rows);
            for method in self.rows.method_def.iter_mut().skip(first_later) {
                method.param_list = Rid::new(shift(method.param_list.row()));
            }
            let pointers = (first..first + count).map(|param| ParamPtrRow {
                param: Rid::new(param),
            });
            self.rows.param_ptr.splice(slot..slot, pointers);
        }
        Ok(())
    }

    /// Returns each column of a row that names a row of `target`: a column
    /// of the table, a coded index with the tag of the table, and the token
    /// of an edit-and-continue row. A list of a run, such as the
    /// `method_list` of a `TypeDef` row, names the first row of its run.
    ///
    /// # Errors
    ///
    /// Returns an error when a row does not encode.
    pub fn references(&self, target: TableId) -> Result<Vec<RowReference>> {
        let mut references = Vec::new();
        for &table in TableId::ALL {
            let columns = columns(table);
            for position in 0..self.rows.row_count(table) {
                let Some(row) = self.rows.any_row(table, position) else {
                    continue;
                };
                let number = to_row(position + 1)?;
                let raw = row.to_raw().map_err(|column| Error::Column {
                    table,
                    row: number,
                    column: columns.get(column).map_or("?", |c| c.name),
                    reason: "the column does not encode",
                })?;
                for (index, column) in columns.iter().enumerate() {
                    let value = raw[index];
                    let named = match column.kind {
                        ColumnKind::Table(named) if named == target && value != 0 => Some(value),
                        ColumnKind::U32
                            if index == 0
                                && matches!(table, TableId::EncLog | TableId::EncMap)
                                && Token(value).table() == Some(target)
                                && !Token(value).is_null() =>
                        {
                            Some(Token(value).row())
                        }
                        ColumnKind::Coded(kind) => kind
                            .try_decode(value)
                            .filter(|token| token.table() == Some(target) && !token.is_null())
                            .map(Token::row),
                        _ => None,
                    };
                    if let Some(target_row) = named {
                        references.push(RowReference {
                            table,
                            row: number,
                            column: column.name,
                            target: target_row,
                        });
                    }
                }
            }
        }
        Ok(references)
    }

    /// Writes `map(row)` for each row number of `target` in every column
    /// that names a row of `target`: a column of the table and a coded index
    /// with the tag of the table. `skip` names the rows whose columns stay.
    fn remap_references(
        &mut self,
        target: TableId,
        map: impl Fn(u32) -> u32,
        skip: impl Fn(TableId, usize) -> bool,
    ) -> Result<()> {
        for &table in TableId::ALL {
            let columns = columns(table);
            for position in 0..self.rows.row_count(table) {
                if skip(table, position) {
                    continue;
                }
                let Some(row) = self.rows.any_row(table, position) else {
                    continue;
                };
                let row_error = |column: usize, reason| Error::Column {
                    table,
                    row: u32::try_from(position + 1).unwrap_or(u32::MAX),
                    column: columns.get(column).map_or("?", |c| c.name),
                    reason,
                };
                let mut raw = row
                    .to_raw()
                    .map_err(|column| row_error(column, "the column does not encode"))?;
                let mut changed = false;
                for (index, column) in columns.iter().enumerate() {
                    let value = raw[index];
                    let mapped = match column.kind {
                        ColumnKind::Table(named) if named == target && value != 0 => map(value),
                        // The edit-and-continue tables hold whole tokens
                        // (II.22.12, II.22.13).
                        ColumnKind::U32
                            if index == 0
                                && matches!(table, TableId::EncLog | TableId::EncMap)
                                && Token(value).table() == Some(target)
                                && !Token(value).is_null() =>
                        {
                            Token::new(target, map(Token(value).row())).0
                        }
                        ColumnKind::Coded(kind) => match kind.try_decode(value) {
                            Some(token) if token.table() == Some(target) && !token.is_null() => {
                                kind.encode(Token::new(target, map(token.row())))
                                    .ok_or_else(|| {
                                        row_error(index, "the new row does not fit the coded index")
                                    })?
                            }
                            _ => value,
                        },
                        _ => value,
                    };
                    if mapped != value {
                        raw[index] = mapped;
                        changed = true;
                    }
                }
                if changed {
                    let row = AnyRow::from_raw(table, &raw)
                        .map_err(|column| row_error(column, "the column does not decode"))?;
                    self.rows.set_any(position, row);
                }
            }
        }
        Ok(())
    }

    /// Sorts each table that ECMA-335 requires to be sorted and that is not
    /// sorted (II.22), with a stable sort by the raw value of its key, and
    /// writes the new row numbers into each column that names a row of the
    /// table. A new number of a row changes the order of the coded indices
    /// that name it, so the tables that such rows sort by come later.
    fn sort_tables(&mut self) -> Result<()> {
        const ORDER: [TableId; 13] = [
            TableId::GenericParam,
            TableId::GenericParamConstraint,
            TableId::InterfaceImpl,
            TableId::MethodImpl,
            TableId::MethodSemantics,
            TableId::ImplMap,
            TableId::DeclSecurity,
            TableId::FieldMarshal,
            TableId::Constant,
            TableId::LocalScope,
            TableId::StateMachineMethod,
            TableId::CustomDebugInformation,
            TableId::CustomAttribute,
        ];
        for table in ORDER {
            let Some(key) = crate::tables::sort_key(table) else {
                continue;
            };
            // The second key of GenericParam is its number, of
            // InterfaceImpl its interface.
            let second = match table {
                TableId::GenericParam => Some(0),
                TableId::InterfaceImpl => Some(1),
                _ => None,
            };
            let count = self.rows.row_count(table);
            let mut keyed = Vec::with_capacity(count);
            for position in 0..count {
                let row = self.rows.any_row(table, position).ok_or(Error::Overflow {
                    structure: table.name(),
                    value: position as u64,
                })?;
                let raw = row.to_raw().map_err(|column| Error::Column {
                    table,
                    row: u32::try_from(position + 1).unwrap_or(u32::MAX),
                    column: columns(table).get(column).map_or("?", |c| c.name),
                    reason: "the column does not encode",
                })?;
                keyed.push((
                    (raw[key], second.map_or(0, |column| raw[column])),
                    position,
                    row,
                ));
            }
            if keyed.is_sorted_by_key(|entry| entry.0.0) {
                continue;
            }
            keyed.sort_by_key(|entry| entry.0);
            // `new_row[old position]` is the new 1-based row.
            let mut new_row = alloc::vec![0; count];
            for (index, &(_, old, row)) in keyed.iter().enumerate() {
                new_row[old] = to_row(index + 1)?;
                self.rows.set_any(index, row);
            }
            self.remap_references(
                table,
                |row| {
                    usize::try_from(row)
                        .ok()
                        .and_then(|row| row.checked_sub(1))
                        .and_then(|old| new_row.get(old).copied())
                        .unwrap_or(row)
                },
                |_, _| false,
            )?;
        }
        Ok(())
    }
}

/// Checks that the coded index `kind` can name `token`.
fn coded(kind: CodedIndexKind, token: Token) -> Result<u32> {
    kind.encode(token).ok_or(Error::Token {
        token,
        reason: "the coded index of the column cannot name the token",
    })
}

/// Returns the token of the row at the 0-based `position` of `table`.
fn row_token(table: TableId, position: usize) -> Result<Token> {
    let row = to_row(position + 1)?;
    if row > 0x00FF_FFFF {
        return Err(Error::Overflow {
            structure: table.name(),
            value: u64::from(row),
        });
    }
    Ok(Token::new(table, row))
}

/// Returns a 1-based row number.
fn to_row(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::Overflow {
        structure: "metadata tables",
        value: value as u64,
    })
}

#[cfg(test)]
mod tests;
