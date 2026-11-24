use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use clrmeta_model::{TableId, Token};

use super::*;
use crate::error::Error;

fn type_ref(row: u32) -> Token {
    Token::new(TableId::TypeRef, row)
}

fn round_trip<S: Signature + PartialEq + core::fmt::Debug>(blob: &[u8], expected: &S) {
    let parsed = S::parse(blob).unwrap();
    assert_eq!(&parsed, expected);
    assert_eq!(parsed.encode().unwrap(), blob);
}

#[test]
fn a_generic_instance_method_signature_reads_and_writes() {
    // instance !!0 M<1>(int32, class [TypeRef 2])
    let blob = [0x30, 0x01, 0x02, 0x1E, 0x00, 0x08, 0x12, 0x09];
    let sig = MethodSig {
        calling_convention: 0x30,
        generic_param_count: 1,
        return_type: TypeSig::MVar(0),
        params: vec![TypeSig::I4, TypeSig::Class(type_ref(2))],
        sentinel: None,
    };
    round_trip(&blob, &sig);
    assert!(sig.has_this() && sig.is_generic());
}

#[test]
fn a_vararg_call_site_keeps_the_place_of_its_sentinel() {
    // vararg void (int32, ..., string, float64)
    let blob = [0x05, 0x03, 0x01, 0x08, 0x41, 0x0E, 0x0D];
    let sig = MethodSig {
        calling_convention: calling_convention::VARARG,
        generic_param_count: 0,
        return_type: TypeSig::Void,
        params: vec![TypeSig::I4, TypeSig::String, TypeSig::R8],
        sentinel: Some(1),
    };
    round_trip(&blob, &sig);
    assert_eq!(sig.fixed_params(), &[TypeSig::I4]);
    assert!(MethodSig::parse(&[0x05, 0x02, 0x01, 0x41, 0x08, 0x41, 0x08]).is_err());
}

#[test]
fn a_field_signature_keeps_its_custom_modifiers_in_order() {
    // modreq(TypeRef 1) modopt(TypeRef 3) int32
    let blob = [0x06, 0x1F, 0x05, 0x20, 0x0D, 0x08];
    let sig = FieldSig {
        field_type: TypeSig::Modified {
            required: true,
            modifier: type_ref(1),
            inner: Box::new(TypeSig::Modified {
                required: false,
                modifier: type_ref(3),
                inner: Box::new(TypeSig::I4),
            }),
        },
    };
    round_trip(&blob, &sig);
    assert_eq!(sig.field_type.unmodified(), &TypeSig::I4);
}

#[test]
fn a_property_signature_reads_its_indexer_parameters() {
    let blob = [0x28, 0x01, 0x0E, 0x08];
    let sig = PropertySig {
        calling_convention: 0x28,
        property_type: TypeSig::String,
        params: vec![TypeSig::I4],
    };
    round_trip(&blob, &sig);
    assert!(sig.has_this());
}

#[test]
fn a_local_signature_reads_pinned_byref_and_typedbyref_locals() {
    // pinned uint8&, typedref, valuetype [TypeDef 4][]
    let blob = [0x07, 0x03, 0x45, 0x10, 0x05, 0x16, 0x1D, 0x11, 0x10];
    let sig = LocalSig {
        locals: vec![
            TypeSig::Pinned(Box::new(TypeSig::ByRef(Box::new(TypeSig::U1)))),
            TypeSig::TypedByRef,
            TypeSig::SzArray(Box::new(TypeSig::ValueType(Token::new(
                TableId::TypeDef,
                4,
            )))),
        ],
    };
    round_trip(&blob, &sig);
}

#[test]
fn a_type_specification_reads_arrays_with_bounds_and_generic_instances() {
    // int32[-3..., 0...4, ...]: rank 3, sizes [?, 5], bounds [-3, 0]
    let array = [0x14, 0x08, 0x03, 0x02, 0x00, 0x05, 0x02, 0x7B, 0x00];
    let shape = ArrayShape {
        rank: 3,
        sizes: vec![0, 5],
        lower_bounds: vec![-3, 0],
    };
    round_trip(&array, &TypeSig::Array(Box::new(TypeSig::I4), shape));

    // valuetype [TypeRef 1]<!0, object>
    let generic = [0x15, 0x11, 0x05, 0x02, 0x13, 0x00, 0x1C];
    let inst = TypeSig::GenericInst {
        value_type: true,
        generic: type_ref(1),
        arguments: vec![TypeSig::Var(0), TypeSig::Object],
    };
    round_trip(&generic, &inst);
}

#[test]
fn a_function_pointer_holds_a_method_signature() {
    // method unmanaged stdcall int* (void*)
    let blob = [0x1B, 0x02, 0x01, 0x0F, 0x08, 0x0F, 0x01];
    let sig = TypeSig::FnPtr(Box::new(MethodSig {
        calling_convention: calling_convention::STDCALL,
        generic_param_count: 0,
        return_type: TypeSig::Ptr(Box::new(TypeSig::I4)),
        params: vec![TypeSig::Ptr(Box::new(TypeSig::Void))],
        sentinel: None,
    }));
    round_trip(&blob, &sig);
}

#[test]
fn a_method_instantiation_reads_its_type_arguments() {
    let blob = [0x0A, 0x02, 0x0E, 0x18];
    round_trip(
        &blob,
        &MethodSpecSig {
            arguments: vec![TypeSig::String, TypeSig::I],
        },
    );
}

#[test]
fn a_stand_alone_signature_dispatches_on_its_first_byte() {
    let locals = StandAloneSignature::parse(&[0x07, 0x01, 0x08]).unwrap();
    assert!(matches!(locals, StandAloneSignature::Locals(_)));
    let call = StandAloneSignature::parse(&[0x02, 0x00, 0x01]).unwrap();
    assert!(matches!(call, StandAloneSignature::Method(_)));
    assert_eq!(call.encode().unwrap(), [0x02, 0x00, 0x01]);
    let field = MemberSignature::parse(&[0x06, 0x0E]).unwrap();
    assert!(matches!(field, MemberSignature::Field(_)));
}

#[test]
fn malformed_signatures_are_errors_with_offsets() {
    // A type token with tag 3.
    assert!(matches!(
        TypeSig::parse(&[0x12, 0x07]),
        Err(Error::Malformed { offset: 1, .. })
    ));
    // Bytes after the end.
    assert!(FieldSig::parse(&[0x06, 0x08, 0x08]).is_err());
    // A sentinel in a type position.
    assert!(TypeSig::parse(&[0x41]).is_err());
    // A count larger than the blob.
    assert!(LocalSig::parse(&[0x07, 0x7F, 0x08]).is_err());
    // A truncated blob.
    assert!(matches!(
        MethodSig::parse(&[0x00, 0x01, 0x01]),
        Err(Error::Truncated { .. })
    ));
    // A field kind in a method signature.
    assert!(MethodSig::parse(&[0x06, 0x00, 0x01]).is_err());
    // A nesting deeper than the limit.
    let mut deep: Vec<u8> = vec![0x0F; 1000];
    deep.push(0x08);
    assert!(TypeSig::parse(&deep).is_err());
    // A token of a table that a type token cannot hold.
    let bad = TypeSig::Class(Token::new(TableId::MethodDef, 1));
    assert!(matches!(bad.encode(), Err(Error::Token { .. })));
}
