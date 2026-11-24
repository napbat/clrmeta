//! The lookups from a row to its owner and from an owner to the rows that
//! refer to it.

use crate::error::{Error, Result};
use crate::metadata::Metadata;
use crate::tables::{
    ClassLayoutRow, CodedIndexKind, ConstantRow, CustomAttributeRow, DeclSecurityRow,
    FieldLayoutRow, FieldMarshalRow, FieldRow, FieldRvaRow, GenericParamConstraintRow,
    GenericParamRow, ImplMapRow, InterfaceImplRow, MethodDefRow, MethodImplRow, MethodSemanticsRow,
    NestedClassRow, ParamRow, TableId, TableRow, TypeDefRow, list_columns,
};
use crate::token::{Rid, Token};

impl Metadata<'_> {
    /// Returns the type that owns a method.
    #[must_use]
    pub fn method_owner(&self, method: Rid<MethodDefRow>) -> Option<Rid<TypeDefRow>> {
        self.list_owner(
            TableId::TypeDef,
            list_columns(TableId::TypeDef)[1],
            method.row(),
        )
        .map(Rid::new)
    }

    /// Returns the type that owns a field.
    #[must_use]
    pub fn field_owner(&self, field: Rid<FieldRow>) -> Option<Rid<TypeDefRow>> {
        self.list_owner(
            TableId::TypeDef,
            list_columns(TableId::TypeDef)[0],
            field.row(),
        )
        .map(Rid::new)
    }

    /// Returns the method that owns a parameter row.
    #[must_use]
    pub fn param_owner(&self, param: Rid<ParamRow>) -> Option<Rid<MethodDefRow>> {
        self.list_owner(
            TableId::MethodDef,
            list_columns(TableId::MethodDef)[0],
            param.row(),
        )
        .map(Rid::new)
    }

    /// Returns the enclosing type of a nested type.
    ///
    /// # Errors
    ///
    /// Returns an error when the `NestedClass` row of the type is not valid.
    pub fn enclosing_type(&self, ty: Rid<TypeDefRow>) -> Result<Option<Rid<TypeDefRow>>> {
        let table = self.tables().table::<NestedClassRow>();
        match table.rows_with_key(0, ty.row()).next() {
            Some(row) => Ok(Some(table.get(row)?.enclosing_class)),
            None => Ok(None),
        }
    }

    /// Returns the types that a type encloses.
    pub fn nested_types(
        &self,
        ty: Rid<TypeDefRow>,
    ) -> impl Iterator<Item = Result<Rid<TypeDefRow>>> + '_ {
        let table = self.tables().table::<NestedClassRow>();
        table
            .raw()
            .rows_with_key(1, ty.row())
            .map(move |row| table.get(Rid::new(row)).map(|r| r.nested_class))
    }

    /// Returns the `rows_with_key` of the rows of `R` whose coded column
    /// holds `token`.
    fn coded_rows<R: TableRow>(
        &self,
        column: usize,
        kind: CodedIndexKind,
        token: Token,
    ) -> Result<impl Iterator<Item = Rid<R>> + '_> {
        let key = kind.encode(token).ok_or(Error::Token {
            token,
            reason: "the column cannot refer to the table of the token",
        })?;
        Ok(self
            .tables()
            .raw_table(R::TABLE)
            .rows_with_key(column, key)
            .map(Rid::new))
    }

    /// Returns the generic parameters of a type or a method, in the order
    /// of the table (by number in a valid file).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Token`] when the token is not a `TypeDef` or a
    /// `MethodDef`.
    pub fn generic_params_of(
        &self,
        owner: Token,
    ) -> Result<impl Iterator<Item = Rid<GenericParamRow>> + '_> {
        self.coded_rows(2, CodedIndexKind::TypeOrMethodDef, owner)
    }

    /// Returns the constraints of a generic parameter.
    pub fn generic_param_constraints_of(
        &self,
        param: Rid<GenericParamRow>,
    ) -> impl Iterator<Item = Rid<GenericParamConstraintRow>> + '_ {
        self.tables()
            .raw_table(TableId::GenericParamConstraint)
            .rows_with_key(0, param.row())
            .map(Rid::new)
    }

    /// Returns the custom attributes of a row.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Token`] when the table of the token cannot own a
    /// custom attribute.
    pub fn custom_attributes_of(
        &self,
        parent: Token,
    ) -> Result<impl Iterator<Item = Rid<CustomAttributeRow>> + '_> {
        self.coded_rows(0, CodedIndexKind::HasCustomAttribute, parent)
    }

    /// Returns the interfaces that a type implements.
    pub fn interfaces_of(
        &self,
        ty: Rid<TypeDefRow>,
    ) -> impl Iterator<Item = Rid<InterfaceImplRow>> + '_ {
        self.tables()
            .raw_table(TableId::InterfaceImpl)
            .rows_with_key(0, ty.row())
            .map(Rid::new)
    }

    /// Returns the explicit method implementations of a type.
    pub fn method_impls_of(
        &self,
        ty: Rid<TypeDefRow>,
    ) -> impl Iterator<Item = Rid<MethodImplRow>> + '_ {
        self.tables()
            .raw_table(TableId::MethodImpl)
            .rows_with_key(0, ty.row())
            .map(Rid::new)
    }

    /// Returns the methods of an event or a property.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Token`] when the token is not an `Event` or a
    /// `Property`.
    pub fn semantics_of(
        &self,
        association: Token,
    ) -> Result<impl Iterator<Item = Rid<MethodSemanticsRow>> + '_> {
        self.coded_rows(2, CodedIndexKind::HasSemantics, association)
    }

    /// Returns the declarative security rows of a type, a method or the
    /// assembly.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Token`] when the table of the token cannot own a
    /// permission set.
    pub fn decl_security_of(
        &self,
        parent: Token,
    ) -> Result<impl Iterator<Item = Rid<DeclSecurityRow>> + '_> {
        self.coded_rows(1, CodedIndexKind::HasDeclSecurity, parent)
    }

    /// Returns the constant of a field, a parameter or a property.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Token`] when the table of the token cannot own a
    /// constant.
    pub fn constant_of(&self, parent: Token) -> Result<Option<Rid<ConstantRow>>> {
        Ok(self
            .coded_rows(1, CodedIndexKind::HasConstant, parent)?
            .next())
    }

    /// Returns the marshalling descriptor row of a field or a parameter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Token`] when the token is not a `Field` or a `Param`.
    pub fn field_marshal_of(&self, parent: Token) -> Result<Option<Rid<FieldMarshalRow>>> {
        Ok(self
            .coded_rows(0, CodedIndexKind::HasFieldMarshal, parent)?
            .next())
    }

    /// Returns the platform invoke import of a field or a method.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Token`] when the token is not a `Field` or a
    /// `MethodDef`.
    pub fn impl_map_of(&self, member: Token) -> Result<Option<Rid<ImplMapRow>>> {
        Ok(self
            .coded_rows(1, CodedIndexKind::MemberForwarded, member)?
            .next())
    }

    /// Returns the layout row of a type.
    #[must_use]
    pub fn class_layout_of(&self, ty: Rid<TypeDefRow>) -> Option<Rid<ClassLayoutRow>> {
        self.tables()
            .raw_table(TableId::ClassLayout)
            .rows_with_key(2, ty.row())
            .next()
            .map(Rid::new)
    }

    /// Returns the explicit offset row of a field.
    #[must_use]
    pub fn field_layout_of(&self, field: Rid<FieldRow>) -> Option<Rid<FieldLayoutRow>> {
        self.tables()
            .raw_table(TableId::FieldLayout)
            .rows_with_key(1, field.row())
            .next()
            .map(Rid::new)
    }

    /// Returns the initial data row of a field.
    #[must_use]
    pub fn field_rva_of(&self, field: Rid<FieldRow>) -> Option<Rid<FieldRvaRow>> {
        self.tables()
            .raw_table(TableId::FieldRva)
            .rows_with_key(1, field.row())
            .next()
            .map(Rid::new)
    }
}
