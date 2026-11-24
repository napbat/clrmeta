//! The schema of every table of ECMA-335 II.22 and of the portable PDB
//! format.

use alloc::vec::Vec;

use super::column::{Column, ColumnKind, ColumnValue, MAX_COLUMNS, RawRow};
use super::define::define_tables;
use super::{CodedIndexKind as C, TableId, TableRow};
use crate::heaps::{BlobIndex, GuidIndex, StringIndex};
use crate::token::{Rid, Token};

const U16: ColumnKind = ColumnKind::U16;
const U32: ColumnKind = ColumnKind::U32;
const STRING: ColumnKind = ColumnKind::Strings;
const GUID: ColumnKind = ColumnKind::Guid;
const BLOB: ColumnKind = ColumnKind::Blob;

const fn table(id: TableId) -> ColumnKind {
    ColumnKind::Table(id)
}

const fn coded(kind: C) -> ColumnKind {
    ColumnKind::Coded(kind)
}

define_tables! {
    /// The module (II.22.30).
    Module = 0x00, ModuleRow, module {
        /// Reserved, zero.
        generation: u16 = U16,
        /// The name of the module file.
        name: StringIndex = STRING,
        /// The module version identifier.
        mvid: GuidIndex = GUID,
        /// The edit-and-continue identifier, or zero.
        enc_id: GuidIndex = GUID,
        /// The edit-and-continue base identifier, or zero.
        enc_base_id: GuidIndex = GUID,
    }
    /// A reference to a type of another scope (II.22.38).
    TypeRef = 0x01, TypeRefRow, type_ref {
        /// The scope of the type: a module, a module reference, an assembly
        /// reference, or the enclosing type reference.
        resolution_scope: Token = coded(C::ResolutionScope),
        /// The name of the type.
        type_name: StringIndex = STRING,
        /// The namespace of the type.
        type_namespace: StringIndex = STRING,
    }
    /// A type definition (II.22.37).
    TypeDef = 0x02, TypeDefRow, type_def {
        /// The `TypeAttributes`.
        flags: u32 = U32,
        /// The name of the type.
        type_name: StringIndex = STRING,
        /// The namespace of the type.
        type_namespace: StringIndex = STRING,
        /// The base type, or a null token.
        extends: Token = coded(C::TypeDefOrRef),
        /// The first field of the type (through `FieldPtr` when present).
        field_list: Rid<FieldRow> = table(TableId::Field),
        /// The first method of the type (through `MethodPtr` when present).
        method_list: Rid<MethodDefRow> = table(TableId::MethodDef),
    }
    /// An indirection to a field, of unoptimized metadata (`#-`).
    FieldPtr = 0x03, FieldPtrRow, field_ptr {
        /// The field.
        field: Rid<FieldRow> = table(TableId::Field),
    }
    /// A field definition (II.22.15).
    Field = 0x04, FieldRow, field {
        /// The `FieldAttributes`.
        flags: u16 = U16,
        /// The name of the field.
        name: StringIndex = STRING,
        /// The field signature.
        signature: BlobIndex = BLOB,
    }
    /// An indirection to a method, of unoptimized metadata (`#-`).
    MethodPtr = 0x05, MethodPtrRow, method_ptr {
        /// The method.
        method: Rid<MethodDefRow> = table(TableId::MethodDef),
    }
    /// A method definition (II.22.26).
    MethodDef = 0x06, MethodDefRow, method_def {
        /// The relative virtual address of the method body, or zero.
        rva: u32 = U32,
        /// The `MethodImplAttributes`.
        impl_flags: u16 = U16,
        /// The `MethodAttributes`.
        flags: u16 = U16,
        /// The name of the method.
        name: StringIndex = STRING,
        /// The method signature.
        signature: BlobIndex = BLOB,
        /// The first parameter of the method (through `ParamPtr` when present).
        param_list: Rid<ParamRow> = table(TableId::Param),
    }
    /// An indirection to a parameter, of unoptimized metadata (`#-`).
    ParamPtr = 0x07, ParamPtrRow, param_ptr {
        /// The parameter.
        param: Rid<ParamRow> = table(TableId::Param),
    }
    /// A parameter definition (II.22.33).
    Param = 0x08, ParamRow, param {
        /// The `ParamAttributes`.
        flags: u16 = U16,
        /// The position: 0 for the return value, 1 for the first parameter.
        sequence: u16 = U16,
        /// The name of the parameter.
        name: StringIndex = STRING,
    }
    /// An interface that a type implements (II.22.23).
    InterfaceImpl = 0x09, InterfaceImplRow, interface_impl {
        /// The type that implements the interface.
        class: Rid<TypeDefRow> = table(TableId::TypeDef),
        /// The interface.
        interface: Token = coded(C::TypeDefOrRef),
    }
    /// A reference to a field or a method of a type (II.22.25).
    MemberRef = 0x0A, MemberRefRow, member_ref {
        /// The owner of the member.
        class: Token = coded(C::MemberRefParent),
        /// The name of the member.
        name: StringIndex = STRING,
        /// The method or field signature.
        signature: BlobIndex = BLOB,
    }
    /// A constant value of a field, a parameter or a property (II.22.9).
    Constant = 0x0B, ConstantRow, constant {
        /// The element type of the constant in the low byte; the high byte
        /// is padding.
        type_and_padding: u16 = U16,
        /// The owner of the constant.
        parent: Token = coded(C::HasConstant),
        /// The value.
        value: BlobIndex = BLOB,
    }
    /// A custom attribute (II.22.10).
    CustomAttribute = 0x0C, CustomAttributeRow, custom_attribute {
        /// The owner of the attribute.
        parent: Token = coded(C::HasCustomAttribute),
        /// The constructor of the attribute.
        attribute_type: Token = coded(C::CustomAttributeType),
        /// The value blob (II.23.3).
        value: BlobIndex = BLOB,
    }
    /// The marshalling descriptor of a field or a parameter (II.22.17).
    FieldMarshal = 0x0D, FieldMarshalRow, field_marshal {
        /// The field or the parameter.
        parent: Token = coded(C::HasFieldMarshal),
        /// The descriptor (II.23.4).
        native_type: BlobIndex = BLOB,
    }
    /// A declarative security permission set (II.22.11).
    DeclSecurity = 0x0E, DeclSecurityRow, decl_security {
        /// The `SecurityAction`.
        action: u16 = U16,
        /// The owner of the permission set.
        parent: Token = coded(C::HasDeclSecurity),
        /// The permission set blob.
        permission_set: BlobIndex = BLOB,
    }
    /// The layout of a type (II.22.8).
    ClassLayout = 0x0F, ClassLayoutRow, class_layout {
        /// The packing size.
        packing_size: u16 = U16,
        /// The size of the type.
        class_size: u32 = U32,
        /// The type.
        parent: Rid<TypeDefRow> = table(TableId::TypeDef),
    }
    /// The offset of a field in an explicit layout (II.22.16).
    FieldLayout = 0x10, FieldLayoutRow, field_layout {
        /// The offset of the field.
        offset: u32 = U32,
        /// The field.
        field: Rid<FieldRow> = table(TableId::Field),
    }
    /// A signature of a local variable list or of a `calli` call site
    /// (II.22.36).
    StandAloneSig = 0x11, StandAloneSigRow, stand_alone_sig {
        /// The signature.
        signature: BlobIndex = BLOB,
    }
    /// The events of a type (II.22.12).
    EventMap = 0x12, EventMapRow, event_map {
        /// The type.
        parent: Rid<TypeDefRow> = table(TableId::TypeDef),
        /// The first event of the type (through `EventPtr` when present).
        event_list: Rid<EventRow> = table(TableId::Event),
    }
    /// An indirection to an event, of unoptimized metadata (`#-`).
    EventPtr = 0x13, EventPtrRow, event_ptr {
        /// The event.
        event: Rid<EventRow> = table(TableId::Event),
    }
    /// An event (II.22.13).
    Event = 0x14, EventRow, event {
        /// The `EventAttributes`.
        event_flags: u16 = U16,
        /// The name of the event.
        name: StringIndex = STRING,
        /// The delegate type of the event.
        event_type: Token = coded(C::TypeDefOrRef),
    }
    /// The properties of a type (II.22.35).
    PropertyMap = 0x15, PropertyMapRow, property_map {
        /// The type.
        parent: Rid<TypeDefRow> = table(TableId::TypeDef),
        /// The first property of the type (through `PropertyPtr` when present).
        property_list: Rid<PropertyRow> = table(TableId::Property),
    }
    /// An indirection to a property, of unoptimized metadata (`#-`).
    PropertyPtr = 0x16, PropertyPtrRow, property_ptr {
        /// The property.
        property: Rid<PropertyRow> = table(TableId::Property),
    }
    /// A property (II.22.34).
    Property = 0x17, PropertyRow, property {
        /// The `PropertyAttributes`.
        flags: u16 = U16,
        /// The name of the property.
        name: StringIndex = STRING,
        /// The property signature.
        signature: BlobIndex = BLOB,
    }
    /// A method of an event or a property (II.22.28).
    MethodSemantics = 0x18, MethodSemanticsRow, method_semantics {
        /// The `MethodSemanticsAttributes`.
        semantics: u16 = U16,
        /// The method.
        method: Rid<MethodDefRow> = table(TableId::MethodDef),
        /// The event or the property.
        association: Token = coded(C::HasSemantics),
    }
    /// An explicit implementation of a method (II.22.27).
    MethodImpl = 0x19, MethodImplRow, method_impl {
        /// The type that holds the implementation.
        class: Rid<TypeDefRow> = table(TableId::TypeDef),
        /// The method that implements the declaration.
        method_body: Token = coded(C::MethodDefOrRef),
        /// The method that the body implements.
        method_declaration: Token = coded(C::MethodDefOrRef),
    }
    /// A reference to another module of the assembly (II.22.31).
    ModuleRef = 0x1A, ModuleRefRow, module_ref {
        /// The name of the module.
        name: StringIndex = STRING,
    }
    /// A type signature (II.22.39).
    TypeSpec = 0x1B, TypeSpecRow, type_spec {
        /// The type signature.
        signature: BlobIndex = BLOB,
    }
    /// A platform invoke import (II.22.22).
    ImplMap = 0x1C, ImplMapRow, impl_map {
        /// The `PInvokeAttributes`.
        mapping_flags: u16 = U16,
        /// The field or the method.
        member_forwarded: Token = coded(C::MemberForwarded),
        /// The name of the imported symbol.
        import_name: StringIndex = STRING,
        /// The module that exports the symbol.
        import_scope: Rid<ModuleRefRow> = table(TableId::ModuleRef),
    }
    /// The initial data of a field (II.22.18).
    FieldRva = 0x1D, FieldRvaRow, field_rva {
        /// The relative virtual address of the data.
        rva: u32 = U32,
        /// The field.
        field: Rid<FieldRow> = table(TableId::Field),
    }
    /// An edit-and-continue log entry.
    EncLog = 0x1E, EncLogRow, enc_log {
        /// The token of the row that the edit changes.
        token: Token = U32,
        /// The edit operation.
        func_code: u32 = U32,
    }
    /// An edit-and-continue token map entry.
    EncMap = 0x1F, EncMapRow, enc_map {
        /// The token of the row.
        token: Token = U32,
    }
    /// The assembly manifest (II.22.2).
    Assembly = 0x20, AssemblyRow, assembly {
        /// The `AssemblyHashAlgorithm`.
        hash_alg_id: u32 = U32,
        /// The major version.
        major_version: u16 = U16,
        /// The minor version.
        minor_version: u16 = U16,
        /// The build number.
        build_number: u16 = U16,
        /// The revision number.
        revision_number: u16 = U16,
        /// The `AssemblyFlags`.
        flags: u32 = U32,
        /// The public key, or zero.
        public_key: BlobIndex = BLOB,
        /// The name of the assembly.
        name: StringIndex = STRING,
        /// The culture, or zero.
        culture: StringIndex = STRING,
    }
    /// A processor of the assembly; not used (II.22.4).
    AssemblyProcessor = 0x21, AssemblyProcessorRow, assembly_processor {
        /// The processor.
        processor: u32 = U32,
    }
    /// An operating system of the assembly; not used (II.22.3).
    AssemblyOs = 0x22, AssemblyOsRow, assembly_os {
        /// The platform identifier.
        os_platform_id: u32 = U32,
        /// The major version.
        os_major_version: u32 = U32,
        /// The minor version.
        os_minor_version: u32 = U32,
    }
    /// A reference to another assembly (II.22.5).
    AssemblyRef = 0x23, AssemblyRefRow, assembly_ref {
        /// The major version.
        major_version: u16 = U16,
        /// The minor version.
        minor_version: u16 = U16,
        /// The build number.
        build_number: u16 = U16,
        /// The revision number.
        revision_number: u16 = U16,
        /// The `AssemblyFlags`.
        flags: u32 = U32,
        /// The public key or its token, or zero.
        public_key_or_token: BlobIndex = BLOB,
        /// The name of the assembly.
        name: StringIndex = STRING,
        /// The culture, or zero.
        culture: StringIndex = STRING,
        /// The hash of the assembly, or zero.
        hash_value: BlobIndex = BLOB,
    }
    /// A processor of a referenced assembly; not used (II.22.7).
    AssemblyRefProcessor = 0x24, AssemblyRefProcessorRow, assembly_ref_processor {
        /// The processor.
        processor: u32 = U32,
        /// The assembly reference.
        assembly_ref: Rid<AssemblyRefRow> = table(TableId::AssemblyRef),
    }
    /// An operating system of a referenced assembly; not used (II.22.6).
    AssemblyRefOs = 0x25, AssemblyRefOsRow, assembly_ref_os {
        /// The platform identifier.
        os_platform_id: u32 = U32,
        /// The major version.
        os_major_version: u32 = U32,
        /// The minor version.
        os_minor_version: u32 = U32,
        /// The assembly reference.
        assembly_ref: Rid<AssemblyRefRow> = table(TableId::AssemblyRef),
    }
    /// A file of the assembly (II.22.19).
    File = 0x26, FileRow, file {
        /// The `FileAttributes`.
        flags: u32 = U32,
        /// The name of the file.
        name: StringIndex = STRING,
        /// The hash of the file.
        hash_value: BlobIndex = BLOB,
    }
    /// A type that another module or assembly defines and this assembly
    /// exports or forwards (II.22.14).
    ExportedType = 0x27, ExportedTypeRow, exported_type {
        /// The `TypeAttributes`.
        flags: u32 = U32,
        /// A hint: the `TypeDef` row of the type in its module.
        type_def_id: u32 = U32,
        /// The name of the type.
        type_name: StringIndex = STRING,
        /// The namespace of the type.
        type_namespace: StringIndex = STRING,
        /// The file, the assembly reference or the enclosing exported type.
        implementation: Token = coded(C::Implementation),
    }
    /// A resource of the assembly (II.22.24).
    ManifestResource = 0x28, ManifestResourceRow, manifest_resource {
        /// The offset of the resource in the resources of the CLI header.
        offset: u32 = U32,
        /// The `ManifestResourceAttributes`.
        flags: u32 = U32,
        /// The name of the resource.
        name: StringIndex = STRING,
        /// The file or the assembly reference, or a null token for a
        /// resource of this file.
        implementation: Token = coded(C::Implementation),
    }
    /// A nested type and its enclosing type (II.22.32).
    NestedClass = 0x29, NestedClassRow, nested_class {
        /// The nested type.
        nested_class: Rid<TypeDefRow> = table(TableId::TypeDef),
        /// The enclosing type.
        enclosing_class: Rid<TypeDefRow> = table(TableId::TypeDef),
    }
    /// A generic parameter of a type or a method (II.22.20).
    GenericParam = 0x2A, GenericParamRow, generic_param {
        /// The 0-based position of the parameter.
        number: u16 = U16,
        /// The `GenericParamAttributes`.
        flags: u16 = U16,
        /// The type or the method.
        owner: Token = coded(C::TypeOrMethodDef),
        /// The name of the parameter.
        name: StringIndex = STRING,
    }
    /// An instantiation of a generic method (II.22.29).
    MethodSpec = 0x2B, MethodSpecRow, method_spec {
        /// The generic method.
        method: Token = coded(C::MethodDefOrRef),
        /// The instantiation signature.
        instantiation: BlobIndex = BLOB,
    }
    /// A constraint of a generic parameter (II.22.21).
    GenericParamConstraint = 0x2C, GenericParamConstraintRow, generic_param_constraint {
        /// The generic parameter.
        owner: Rid<GenericParamRow> = table(TableId::GenericParam),
        /// The type that constrains the parameter.
        constraint: Token = coded(C::TypeDefOrRef),
    }
    /// A source document (portable PDB).
    Document = 0x30, DocumentRow, document {
        /// The document name blob.
        name: BlobIndex = BLOB,
        /// The hash algorithm.
        hash_algorithm: GuidIndex = GUID,
        /// The hash of the document.
        hash: BlobIndex = BLOB,
        /// The language of the document.
        language: GuidIndex = GUID,
    }
    /// The sequence points of a method (portable PDB).
    MethodDebugInformation = 0x31, MethodDebugInformationRow, method_debug_information {
        /// The document, or zero.
        document: Rid<DocumentRow> = table(TableId::Document),
        /// The sequence points blob.
        sequence_points: BlobIndex = BLOB,
    }
    /// A scope of local variables and constants (portable PDB).
    LocalScope = 0x32, LocalScopeRow, local_scope {
        /// The method.
        method: Rid<MethodDefRow> = table(TableId::MethodDef),
        /// The import scope.
        import_scope: Rid<ImportScopeRow> = table(TableId::ImportScope),
        /// The first local variable of the scope.
        variable_list: Rid<LocalVariableRow> = table(TableId::LocalVariable),
        /// The first local constant of the scope.
        constant_list: Rid<LocalConstantRow> = table(TableId::LocalConstant),
        /// The IL offset of the start of the scope.
        start_offset: u32 = U32,
        /// The length of the scope in bytes of IL.
        length: u32 = U32,
    }
    /// A local variable (portable PDB).
    LocalVariable = 0x33, LocalVariableRow, local_variable {
        /// The `LocalVariableAttributes`.
        attributes: u16 = U16,
        /// The slot of the variable.
        index: u16 = U16,
        /// The name of the variable.
        name: StringIndex = STRING,
    }
    /// A local constant (portable PDB).
    LocalConstant = 0x34, LocalConstantRow, local_constant {
        /// The name of the constant.
        name: StringIndex = STRING,
        /// The constant signature blob.
        signature: BlobIndex = BLOB,
    }
    /// A scope of namespace imports (portable PDB).
    ImportScope = 0x35, ImportScopeRow, import_scope {
        /// The enclosing scope, or zero.
        parent: Rid<ImportScopeRow> = table(TableId::ImportScope),
        /// The imports blob.
        imports: BlobIndex = BLOB,
    }
    /// The kickoff method of a state machine (portable PDB).
    StateMachineMethod = 0x36, StateMachineMethodRow, state_machine_method {
        /// The `MoveNext` method of the state machine.
        move_next_method: Rid<MethodDefRow> = table(TableId::MethodDef),
        /// The method that starts the state machine.
        kickoff_method: Rid<MethodDefRow> = table(TableId::MethodDef),
    }
    /// Custom debug information (portable PDB).
    CustomDebugInformation = 0x37, CustomDebugInformationRow, custom_debug_information {
        /// The owner of the information.
        parent: Token = coded(C::HasCustomDebugInformation),
        /// The kind of the information.
        kind: GuidIndex = GUID,
        /// The value.
        value: BlobIndex = BLOB,
    }
}

impl ConstantRow {
    /// Returns the element type of the constant (II.23.1.16).
    #[must_use]
    pub const fn element_type(&self) -> u8 {
        self.type_and_padding.to_le_bytes()[0]
    }
}
