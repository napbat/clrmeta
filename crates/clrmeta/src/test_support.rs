//! A small module that the unit tests build with the writer and read back.

use alloc::vec::Vec;

use clrmeta_model::{
    FieldSig, LocalSig, MethodSig, MethodSpecSig, TableId, Token, TypeSig, calling_convention as cc,
};

use crate::heaps::{BlobHeapBuilder, BlobIndex, StringIndex, StringsHeapBuilder};
use crate::signature::Signature;
use crate::tables::{
    AssemblyRefRow, FieldRow, GenericParamRow, MemberRefRow, MethodDefRow, MethodSpecRow,
    ModuleRow, NestedClassRow, ParamRow, StandAloneSigRow, TableRows, TypeDefRow, TypeRefRow,
};
use crate::token::Rid;
use crate::write::MetadataBuilder;

/// The token of the `ldstr` string "hello" of the sample.
pub(crate) const HELLO: Token = Token(0x7000_0001);

/// The signatures of the sample, in the `#Blob` heap.
struct Blobs {
    int_field: BlobIndex,
    string_field: BlobIndex,
    ctor: BlobIndex,
    add: BlobIndex,
    get: BlobIndex,
    spec: BlobIndex,
    locals: BlobIndex,
}

fn method(calling_convention: u8, return_type: TypeSig, params: Vec<TypeSig>) -> Vec<u8> {
    MethodSig {
        calling_convention,
        generic_param_count: u32::from(calling_convention & cc::GENERIC != 0),
        return_type,
        params,
        sentinel: None,
    }
    .encode()
    .unwrap()
}

fn blobs(heap: &mut BlobHeapBuilder) -> Blobs {
    let mut add = |bytes: Vec<u8>| heap.add(&bytes).unwrap();
    Blobs {
        int_field: add(FieldSig {
            field_type: TypeSig::I4,
        }
        .encode()
        .unwrap()),
        string_field: add(FieldSig {
            field_type: TypeSig::String,
        }
        .encode()
        .unwrap()),
        ctor: add(method(cc::HAS_THIS, TypeSig::Void, Vec::new())),
        add: add(method(cc::DEFAULT, TypeSig::I4, alloc::vec![TypeSig::I4])),
        get: add(method(cc::GENERIC, TypeSig::MVar(0), Vec::new())),
        spec: add(MethodSpecSig {
            arguments: alloc::vec![TypeSig::I4],
        }
        .encode()
        .unwrap()),
        locals: add(LocalSig {
            locals: alloc::vec![TypeSig::I4, TypeSig::String],
        }
        .encode()
        .unwrap()),
    }
}

/// Adds the module, the assembly reference, the type references and the
/// type definitions.
fn types(strings: &mut StringsHeapBuilder, rows: &mut TableRows) {
    let mut name = |text: &str| strings.add(text).unwrap();
    rows.module.push(ModuleRow {
        name: name("sample.dll"),
        ..ModuleRow::default()
    });
    rows.assembly_ref.push(AssemblyRefRow {
        major_version: 4,
        name: name("mscorlib"),
        ..AssemblyRefRow::default()
    });
    for type_name in ["Object", "Enum"] {
        rows.type_ref.push(TypeRefRow {
            resolution_scope: Token::new(TableId::AssemblyRef, 1),
            type_name: name(type_name),
            type_namespace: name("System"),
        });
    }
    let defs = [
        ("<Module>", "", Token::new(TableId::TypeDef, 0), 1, 1),
        ("Outer", "Ns", Token::new(TableId::TypeRef, 1), 1, 1),
        ("Inner", "", Token::new(TableId::TypeRef, 1), 2, 3),
        ("Color", "Ns", Token::new(TableId::TypeRef, 2), 3, 4),
    ];
    for (type_name, namespace, extends, field_list, method_list) in defs {
        rows.type_def.push(TypeDefRow {
            flags: 0,
            type_name: name(type_name),
            type_namespace: name(namespace),
            extends,
            field_list: Rid::new(field_list),
            method_list: Rid::new(method_list),
        });
    }
    rows.nested_class.push(NestedClassRow {
        nested_class: Rid::new(3),
        enclosing_class: Rid::new(2),
    });
}

/// Adds the fields, the methods, the parameter, the member references, the
/// generic parameter, the method instantiation and the local signature.
fn members(strings: &mut StringsHeapBuilder, rows: &mut TableRows, blobs: &Blobs) {
    let mut name = |text: &str| strings.add(text).unwrap();
    let fields = [
        ("count", blobs.int_field, 0x0006),
        ("field", blobs.string_field, 0x0016),
        ("value__", blobs.int_field, 0x0606),
    ];
    for (field_name, signature, flags) in fields {
        rows.field.push(FieldRow {
            flags,
            name: name(field_name),
            signature,
        });
    }
    let methods = [
        (".ctor", blobs.ctor, 0x1886, 1),
        ("Add", blobs.add, 0x0016, 1),
        ("Get", blobs.get, 0x0016, 2),
    ];
    for (method_name, signature, flags, param_list) in methods {
        rows.method_def.push(MethodDefRow {
            rva: 0,
            impl_flags: 0,
            flags,
            name: name(method_name),
            signature,
            param_list: Rid::new(param_list),
        });
    }
    rows.param.push(ParamRow {
        flags: 0,
        sequence: 1,
        name: name("a"),
    });
    let parent = Token::new(TableId::TypeRef, 1);
    rows.member_ref.push(MemberRefRow {
        class: parent,
        name: name(".ctor"),
        signature: blobs.ctor,
    });
    rows.member_ref.push(MemberRefRow {
        class: parent,
        name: name("x"),
        signature: blobs.int_field,
    });
    rows.generic_param.push(GenericParamRow {
        number: 0,
        flags: 0,
        owner: Token::new(TableId::MethodDef, 3),
        name: name("T"),
    });
    rows.method_spec.push(MethodSpecRow {
        method: Token::new(TableId::MethodDef, 3),
        instantiation: blobs.spec,
    });
    rows.stand_alone_sig.push(StandAloneSigRow {
        signature: blobs.locals,
    });
}

/// Builds the sample:
///
/// - `TypeDef` 1 `<Module>`, 2 `Ns.Outer` (field 1, methods 1 and 2), 3
///   `Ns.Outer/Inner` (field 2, method 3), 4 `Ns.Color`, an enum (field 3).
/// - `TypeRef` 1 `System.Object`, 2 `System.Enum`, both in `AssemblyRef` 1.
/// - `MethodDef` 1 `.ctor` (instance void), 2 `Add` (static int32(int32),
///   one `Param` row), 3 `Get<T>` (static `!!0()`).
/// - `MemberRef` 1 `Object::.ctor` (a method), 2 `Object::x` (a field).
/// - `MethodSpec` 1 `Get<int32>`, `StandAloneSig` 1 (int32, string).
pub(crate) fn sample() -> MetadataBuilder {
    let mut builder = MetadataBuilder::new("v4.0.30319");
    types(&mut builder.strings, &mut builder.rows);
    let blobs = blobs(&mut builder.blobs);
    members(&mut builder.strings, &mut builder.rows, &blobs);
    assert_eq!(builder.user_strings.add("hello").unwrap(), HELLO);
    assert_eq!(builder.strings.add("").unwrap(), StringIndex::default());
    builder
}
