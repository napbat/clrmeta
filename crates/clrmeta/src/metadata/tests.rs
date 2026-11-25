use alloc::string::ToString;
use alloc::vec::Vec;

use clrmeta_model::{FieldSig, MethodSig, TableId, Token, TypeSig};

use crate::custom_attribute::{EnumIndex, EnumResolver, MetadataResolver};
use crate::error::Error;
use crate::metadata::Metadata;
use crate::resolve::{Member, TypeRef};
use crate::tables::{AnyRow, MethodDefRow, TypeDefRow};
use crate::test_support::{HELLO, sample};
use crate::token::Rid;
use crate::validate::Location;

mod quirks;

fn rows<R>(list: impl Iterator<Item = Rid<R>>) -> Vec<u32> {
    list.map(Rid::row).collect()
}

#[test]
fn the_lists_and_their_owners_agree() {
    let bytes = sample().write().unwrap();
    let md = Metadata::parse(&bytes).unwrap();
    assert_eq!(md.version(), "v4.0.30319");
    assert_eq!(md.tables_stream_name(), b"#~");
    let outer = Rid::<TypeDefRow>::new(2);
    let inner = Rid::<TypeDefRow>::new(3);
    assert_eq!(rows(md.methods_of(Rid::new(1)).unwrap()), [] as [u32; 0]);
    assert_eq!(rows(md.methods_of(outer).unwrap()), [1, 2]);
    assert_eq!(rows(md.methods_of(inner).unwrap()), [3]);
    assert_eq!(rows(md.fields_of(outer).unwrap()), [1]);
    assert_eq!(rows(md.fields_of(Rid::new(4)).unwrap()), [3]);
    assert_eq!(rows(md.params_of(Rid::new(1)).unwrap()), [] as [u32; 0]);
    assert_eq!(rows(md.params_of(Rid::new(2)).unwrap()), [1]);
    assert_eq!(rows(md.params_of(Rid::new(3)).unwrap()), [] as [u32; 0]);
    assert_eq!(md.method_owner(Rid::new(1)), Some(outer));
    assert_eq!(md.method_owner(Rid::new(3)), Some(inner));
    assert_eq!(md.field_owner(Rid::new(2)), Some(inner));
    assert_eq!(md.param_owner(Rid::new(1)), Some(Rid::new(2)));
    assert!(md.methods_of(Rid::new(9)).is_err());
    assert_eq!(md.events_of(outer).unwrap().count(), 0);
}

#[test]
fn nested_types_and_generic_parameters_are_found() {
    let bytes = sample().write().unwrap();
    let md = Metadata::parse(&bytes).unwrap();
    let outer = Rid::<TypeDefRow>::new(2);
    let inner = Rid::<TypeDefRow>::new(3);
    assert_eq!(md.enclosing_type(inner).unwrap(), Some(outer));
    assert_eq!(md.enclosing_type(outer).unwrap(), None);
    let nested: Vec<_> = md.nested_types(outer).map(Result::unwrap).collect();
    assert_eq!(nested, [inner]);
    assert_eq!(
        md.type_name(inner.token()).unwrap().to_string(),
        "Ns.Outer/Inner"
    );
    assert_eq!(
        md.type_name(Token::new(TableId::TypeRef, 2))
            .unwrap()
            .to_string(),
        "System.Enum"
    );
    assert!(md.type_name(Token::new(TableId::MethodDef, 1)).is_err());
    let params = rows(
        md.generic_params_of(Token::new(TableId::MethodDef, 3))
            .unwrap(),
    );
    assert_eq!(params, [1]);
    assert!(md.generic_params_of(Token::new(TableId::Field, 1)).is_err());
}

#[test]
fn the_resolver_checks_the_kind_of_each_token() {
    let bytes = sample().write().unwrap();
    let md = Metadata::parse(&bytes).unwrap();
    let resolver = md.resolver();
    let add = resolver.method(Token::new(TableId::MethodDef, 2)).unwrap();
    assert_eq!(add.name, "Add");
    assert_eq!(add.owner, Token::new(TableId::TypeDef, 2));
    assert_eq!(add.signature.params, [TypeSig::I4]);
    let ctor = resolver.method(Token::new(TableId::MemberRef, 1)).unwrap();
    assert_eq!(ctor.owner, Token::new(TableId::TypeRef, 1));
    assert!(ctor.signature.has_this());
    let spec = resolver.method(Token::new(TableId::MethodSpec, 1)).unwrap();
    assert_eq!(spec.definition, Token::new(TableId::MethodDef, 3));
    assert_eq!(spec.instantiation.unwrap().arguments, [TypeSig::I4]);

    let field_ref = Token::new(TableId::MemberRef, 2);
    assert!(matches!(
        resolver.method(field_ref),
        Err(Error::Token { .. })
    ));
    assert_eq!(
        resolver.field(field_ref).unwrap().signature,
        FieldSig {
            field_type: TypeSig::I4
        }
    );
    assert!(resolver.field(Token::new(TableId::MemberRef, 1)).is_err());
    assert_eq!(
        resolver.field(Token::new(TableId::Field, 2)).unwrap().name,
        "field"
    );
    assert!(matches!(
        resolver.member(field_ref).unwrap(),
        Member::Field(_)
    ));
    assert!(matches!(
        resolver.type_ref(Token::new(TableId::TypeDef, 3)).unwrap(),
        TypeRef::Named { .. }
    ));
    assert_eq!(
        resolver.user_string(HELLO).unwrap().to_string().unwrap(),
        "hello"
    );
    assert!(
        resolver
            .stand_alone(Token::new(TableId::StandAloneSig, 1))
            .is_ok()
    );
    assert!(
        resolver
            .stand_alone(Token::new(TableId::MethodDef, 1))
            .is_err()
    );
    let sig: MethodSig = md.method_signature(Rid::<MethodDefRow>::new(3)).unwrap();
    assert!(sig.is_generic());
    assert!(matches!(
        md.row(Token::new(TableId::Param, 1)).unwrap(),
        AnyRow::Param(_)
    ));
}

#[test]
fn the_metadata_resolver_finds_enums_and_system_type() {
    let bytes = sample().write().unwrap();
    let md = Metadata::parse(&bytes).unwrap();
    let index = EnumIndex::new(&[&md]);
    assert_eq!(index.len(), 1);
    let resolver = MetadataResolver::new(&md, &index);
    let color = Token::new(TableId::TypeDef, 4);
    assert_eq!(
        resolver.underlying_type_of_token(color),
        Some(clrmeta_model::element_type::I4)
    );
    assert_eq!(
        resolver.underlying_type_of_name("Ns.Color, sample"),
        Some(0x08)
    );
    assert_eq!(
        resolver.underlying_type_of_token(Token::new(TableId::TypeDef, 2)),
        None
    );
    assert!(!resolver.is_system_type(Token::new(TableId::TypeRef, 1)));
}

#[test]
fn a_valid_module_has_no_issues_and_a_broken_one_has_named_issues() {
    let bytes = sample().write().unwrap();
    let md = Metadata::parse(&bytes).unwrap();
    assert_eq!(md.validate(), []);

    let mut broken = sample();
    broken.rows.type_def[1].method_list = Rid::new(9);
    broken.rows.field[0].signature = broken.rows.member_ref[0].signature;
    let bytes = broken.write().unwrap();
    let md = Metadata::parse(&bytes).unwrap();
    let issues: Vec<_> = md.validate().into_iter().map(|i| i.location).collect();
    let column = |table, row, column| Location::Column { table, row, column };
    assert!(issues.contains(&column(TableId::TypeDef, 2, "method_list")));
    assert!(issues.contains(&column(TableId::TypeDef, 3, "method_list")));
    assert!(issues.contains(&column(TableId::Field, 1, "signature")));
}

#[test]
fn malformed_metadata_is_an_error() {
    assert!(Metadata::parse(&[]).is_err());
    let bytes = sample().write().unwrap();
    assert!(Metadata::parse(&bytes[..bytes.len() / 2]).is_err());
}
