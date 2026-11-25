use alloc::vec;
use alloc::vec::Vec;

use crate::heaps::{BlobHeap, BlobIndex, Guid, StringsHeap};
use crate::metadata::Metadata;
use crate::pdb::PdbStream;
use crate::tables::{
    CustomAttributeRow, DocumentRow, EncLogRow, EncMapRow, GenericParamConstraintRow,
    GenericParamRow, LocalScopeRow, MethodDebugInformationRow, MethodDefRow, MethodPtrRow,
    StateMachineMethodRow, TableId, TableRows,
};
use crate::test_support::sample;
use crate::token::{Rid, Token};
use crate::write::{MetadataBuilder, MethodRenumbering, StreamSlot};

fn method_def(row: u32) -> Token {
    Token::new(TableId::MethodDef, row)
}

fn type_def(row: u32) -> Token {
    Token::new(TableId::TypeDef, row)
}

/// Writes `builder`, reads it back, checks that the reader finds no issue,
/// and returns the rows that it reads.
fn written(builder: &MetadataBuilder) -> (Vec<u8>, TableRows) {
    let bytes = builder.write().unwrap();
    let metadata = Metadata::parse(&bytes).unwrap();
    assert_eq!(metadata.validate(), [], "the written metadata is valid");
    let rows = metadata.tables().to_rows().unwrap();
    assert_eq!(rows, builder.rows, "the rows read back");
    (bytes, rows)
}

/// Returns the names of the methods of the type at the 0-based `index`.
fn method_names(builder: &MetadataBuilder, index: usize) -> Vec<&str> {
    let types = &builder.rows.type_def;
    let start = types[index].method_list.row() as usize;
    let end = types
        .get(index + 1)
        .map_or(builder.rows.method_def.len() + 1, |next| {
            next.method_list.row() as usize
        });
    let strings = StringsHeap::new(builder.strings.as_bytes());
    builder.rows.method_def[start - 1..end - 1]
        .iter()
        .map(|row| strings.get(row.name).unwrap())
        .collect()
}

/// Returns a new static method named `name` with the signature
/// `int32(int32)`.
fn new_method(builder: &mut MetadataBuilder, name: &str) -> MethodDefRow {
    MethodDefRow {
        rva: 0x2000,
        impl_flags: 0,
        flags: 0x0096,
        name: builder.strings.add(name).unwrap(),
        signature: builder.blobs.add(&[0x00, 0x01, 0x08, 0x08]).unwrap(),
        param_list: Rid::new(0),
    }
}

#[test]
fn each_reference_is_added_once_and_reads_back() {
    let mut builder = sample();
    let mscorlib = builder
        .add_assembly_ref("mscorlib", [4, 0, 0, 0], &[], "")
        .unwrap();
    assert_eq!(mscorlib, Token::new(TableId::AssemblyRef, 1));
    let token = [0xB0, 0x3F, 0x5F, 0x7F, 0x11, 0xD5, 0x0A, 0x3A];
    let console = builder
        .add_assembly_ref("System.Console", [8, 0, 0, 0], &token, "")
        .unwrap();
    assert_eq!(console, Token::new(TableId::AssemblyRef, 2));
    assert_eq!(builder.rows.assembly_ref[1].flags, 0, "a key token");
    assert_eq!(
        builder.add_assembly_ref("System.Console", [9, 0, 0, 0], &token, ""),
        Ok(console)
    );

    let object = builder.add_type_ref(mscorlib, "System", "Object").unwrap();
    assert_eq!(object, Token::new(TableId::TypeRef, 1), "an equal row");
    let class = builder.add_type_ref(console, "System", "Console").unwrap();
    assert_eq!(class, Token::new(TableId::TypeRef, 3));
    assert_eq!(
        builder.add_type_ref(console, "System", "Console"),
        Ok(class)
    );
    assert!(builder.add_type_ref(method_def(1), "System", "X").is_err());

    let write_line = [0x00, 0x01, 0x01, 0x0E];
    let member = builder
        .add_member_ref(class, "WriteLine", &write_line)
        .unwrap();
    assert_eq!(member, Token::new(TableId::MemberRef, 3));
    assert_eq!(
        builder.add_member_ref(class, "WriteLine", &write_line),
        Ok(member)
    );
    let ctor = builder
        .add_member_ref(object, ".ctor", &[0x20, 0x00, 0x01])
        .unwrap();
    assert_eq!(ctor, Token::new(TableId::MemberRef, 1), "an equal row");
    assert!(
        builder
            .add_member_ref(Token::new(TableId::Field, 1), "x", &[0x06, 0x08])
            .is_err()
    );

    let list = [0x15, 0x12, 0x09, 0x01, 0x08];
    let spec = builder.add_type_spec(&list).unwrap();
    assert_eq!(spec, Token::new(TableId::TypeSpec, 1));
    assert_eq!(builder.add_type_spec(&list), Ok(spec));

    let get = builder
        .add_method_spec(method_def(3), &[0x0A, 0x01, 0x08])
        .unwrap();
    assert_eq!(get, Token::new(TableId::MethodSpec, 1), "an equal row");
    let other = builder
        .add_method_spec(method_def(3), &[0x0A, 0x01, 0x0E])
        .unwrap();
    assert_eq!(other, Token::new(TableId::MethodSpec, 2));
    assert!(
        builder
            .add_method_spec(type_def(2), &[0x0A, 0x01, 0x08])
            .is_err()
    );

    let locals = builder
        .add_stand_alone_sig(&[0x07, 0x02, 0x08, 0x0E])
        .unwrap();
    assert_eq!(
        locals,
        Token::new(TableId::StandAloneSig, 1),
        "an equal row"
    );
    let more = builder
        .add_stand_alone_sig(&[0x07, 0x01, 0x12, 0x0D])
        .unwrap();
    assert_eq!(more, Token::new(TableId::StandAloneSig, 2));

    let string = builder.user_strings.add("edited").unwrap();
    assert_eq!(builder.user_strings.add("edited"), Ok(string));

    let (bytes, rows) = written(&builder);
    let metadata = Metadata::parse(&bytes).unwrap();
    let blobs = metadata.blobs();
    assert_eq!(
        blobs.get(rows.member_ref[2].signature).unwrap(),
        &write_line
    );
    assert_eq!(
        metadata.strings().get(rows.type_ref[2].type_name).unwrap(),
        "Console"
    );
    assert_eq!(
        metadata
            .user_strings()
            .get_token(string)
            .unwrap()
            .to_string()
            .unwrap(),
        "edited"
    );
}

#[test]
fn a_method_signature_changes() {
    let mut builder = sample();
    builder
        .set_method_signature(method_def(2), &[0x00, 0x01, 0x0A, 0x0A])
        .unwrap();
    let (bytes, rows) = written(&builder);
    let metadata = Metadata::parse(&bytes).unwrap();
    assert_eq!(
        metadata.blobs().get(rows.method_def[1].signature).unwrap(),
        &[0x00, 0x01, 0x0A, 0x0A]
    );
    assert!(
        builder
            .set_method_signature(method_def(4), &[0x00, 0x00, 0x01])
            .is_err()
    );
    assert!(
        builder
            .set_method_signature(type_def(1), &[0x00, 0x00, 0x01])
            .is_err()
    );
}

/// The sample with rows that sort by a method: an attribute of `Get` and
/// one of `Inner`, a generic parameter of `Color` after the one of `Get`,
/// and a constraint of the parameter of `Get`.
fn sorted_sample() -> MetadataBuilder {
    let mut builder = sample();
    let ctor = Token::new(TableId::MemberRef, 1);
    for parent in [method_def(3), type_def(3)] {
        builder.rows.custom_attribute.push(CustomAttributeRow {
            parent,
            attribute_type: ctor,
            value: BlobIndex(0),
        });
    }
    let name = builder.strings.add("U").unwrap();
    builder.rows.generic_param.push(GenericParamRow {
        number: 0,
        flags: 0,
        owner: type_def(4),
        name,
    });
    builder
        .rows
        .generic_param_constraint
        .push(GenericParamConstraintRow {
            owner: Rid::new(1),
            constraint: Token::new(TableId::TypeRef, 1),
        });
    written(&builder);
    builder
}

#[test]
fn a_new_method_goes_to_its_type_and_the_later_methods_get_new_numbers() {
    let mut builder = sorted_sample();
    let row = new_method(&mut builder, "Twice");
    let mut renumbering = MethodRenumbering::default();
    let token = builder
        .add_method(type_def(2), row, &["value"], &mut renumbering)
        .unwrap();
    assert_eq!(token, method_def(3));
    assert_eq!(method_names(&builder, 1), [".ctor", "Add", "Twice"]);
    assert_eq!(method_names(&builder, 2), ["Get"]);
    assert_eq!(method_names(&builder, 3), [] as [&str; 0]);
    // The Param row of the new method goes before the run of Get, which
    // starts one row later.
    assert_eq!(builder.rows.method_def[2].param_list, Rid::new(2));
    assert_eq!(builder.rows.method_def[3].param_list, Rid::new(3));
    assert_eq!(builder.rows.param[1].sequence, 1);
    assert_eq!(
        StringsHeap::new(builder.strings.as_bytes())
            .get(builder.rows.param[1].name)
            .unwrap(),
        "value"
    );
    assert_eq!(
        builder.rows.method_def[1].param_list,
        Rid::new(1),
        "Add keeps its run"
    );
    assert!(!renumbering.is_identity());
    assert_eq!(renumbering.token(method_def(2)), method_def(2));
    assert_eq!(renumbering.token(method_def(3)), method_def(4));
    assert_eq!(
        renumbering.token(Token::new(TableId::MemberRef, 3)),
        Token::new(TableId::MemberRef, 3)
    );
    assert_eq!(renumbering.added().collect::<Vec<_>>(), [token]);
    let rows = &builder.rows;
    assert_eq!(rows.method_spec[0].method, method_def(4));
    // MethodDef 4 sorts after TypeDef 3 and TypeDef 4 now: the attribute
    // and the generic parameter of Get move, and the constraint follows
    // its parameter.
    assert_eq!(rows.custom_attribute[0].parent, type_def(3));
    assert_eq!(rows.custom_attribute[1].parent, method_def(4));
    assert_eq!(rows.generic_param[0].owner, type_def(4));
    assert_eq!(rows.generic_param[1].owner, method_def(4));
    assert_eq!(rows.generic_param_constraint[0].owner, Rid::new(2));
    written(&builder);

    // A second method goes before the first: the first gets a new number.
    let row = new_method(&mut builder, "First");
    let first = builder
        .add_method(type_def(1), row, &[], &mut renumbering)
        .unwrap();
    assert_eq!(first, method_def(1));
    assert_eq!(method_names(&builder, 0), ["First"]);
    assert_eq!(method_names(&builder, 1), [".ctor", "Add", "Twice"]);
    assert_eq!(
        renumbering.added().collect::<Vec<_>>(),
        [method_def(4), first]
    );
    assert_eq!(renumbering.token(method_def(1)), method_def(2));
    assert_eq!(renumbering.token(method_def(3)), method_def(5));
    written(&builder);
}

#[test]
fn a_new_method_of_the_last_type_renumbers_nothing() {
    let mut builder = sample();
    let row = new_method(&mut builder, "Last");
    let mut renumbering = MethodRenumbering::default();
    let token = builder
        .add_method(type_def(4), row, &["a", "b"], &mut renumbering)
        .unwrap();
    assert_eq!(token, method_def(4));
    assert!(renumbering.is_identity());
    assert_eq!(method_names(&builder, 3), ["Last"]);
    assert_eq!(
        builder.rows.method_def[3].param_list,
        Rid::new(2),
        "the run after the last Param row"
    );
    assert_eq!(builder.rows.param.len(), 3);
    assert_eq!(builder.rows.param[2].sequence, 2);
    written(&builder);
}

#[test]
fn a_new_method_with_a_method_pointer_table_keeps_every_number() {
    let mut builder = sample();
    for method in 1..=3 {
        builder.rows.method_ptr.push(MethodPtrRow {
            method: Rid::new(method),
        });
    }
    builder.uncompressed = true;
    written(&builder);
    let row = new_method(&mut builder, "Twice");
    let mut renumbering = MethodRenumbering::default();
    let token = builder
        .add_method(type_def(2), row, &["value"], &mut renumbering)
        .unwrap();
    assert_eq!(token, method_def(4), "the last MethodDef row");
    assert!(renumbering.is_identity());
    let pointers: Vec<u32> = (builder.rows.method_ptr.iter())
        .map(|row| row.method.row())
        .collect();
    assert_eq!(pointers, [1, 2, 4, 3]);
    assert_eq!(builder.rows.type_def[2].method_list, Rid::new(4));
    assert_eq!(builder.rows.type_def[3].method_list, Rid::new(5));
    written(&builder);
}

#[test]
fn a_method_is_refused_without_a_type() {
    let mut builder = sample();
    let row = new_method(&mut builder, "Twice");
    let mut renumbering = MethodRenumbering::default();
    assert!(
        builder
            .add_method(type_def(5), row, &[], &mut renumbering)
            .is_err()
    );
    assert!(
        builder
            .add_method(method_def(1), row, &[], &mut renumbering)
            .is_err()
    );
    assert_eq!(builder.rows.method_def.len(), 3, "nothing changed");
    assert_eq!(renumbering, MethodRenumbering::default());
}

#[test]
fn the_edit_and_continue_tables_name_the_new_numbers() {
    let mut builder = sample();
    for token in [method_def(1), method_def(3), Token::new(TableId::Param, 1)] {
        builder.rows.enc_log.push(EncLogRow {
            token,
            func_code: 0,
        });
        builder.rows.enc_map.push(EncMapRow { token });
    }
    let row = new_method(&mut builder, "Twice");
    let mut renumbering = MethodRenumbering::default();
    builder
        .add_method(type_def(2), row, &["value"], &mut renumbering)
        .unwrap();
    let logged: Vec<Token> = builder.rows.enc_log.iter().map(|row| row.token).collect();
    let mapped: Vec<Token> = builder.rows.enc_map.iter().map(|row| row.token).collect();
    let expected = [method_def(1), method_def(4), Token::new(TableId::Param, 1)];
    assert_eq!(logged, expected);
    assert_eq!(mapped, expected);
    written(&builder);
}

#[test]
fn the_debug_tables_of_a_portable_pdb_follow_the_new_numbers() {
    let mut builder = sample();
    let mut rows = [0; 64];
    rows[TableId::MethodDef as usize] = 3;
    builder.pdb = Some(PdbStream {
        id: [1; 20],
        entry_point: method_def(3),
        referenced_type_system_tables: 1 << TableId::MethodDef as u8,
        type_system_table_rows: rows,
    });
    builder.streams.insert(0, StreamSlot::Pdb);
    let language = builder.guids.add(Guid([9; 16])).unwrap();
    builder.rows.document.push(DocumentRow {
        language,
        ..DocumentRow::default()
    });
    for _ in 0..3 {
        builder
            .rows
            .method_debug_information
            .push(MethodDebugInformationRow {
                document: Rid::new(1),
                ..MethodDebugInformationRow::default()
            });
    }
    builder.rows.local_scope.push(LocalScopeRow {
        method: Rid::new(3),
        variable_list: Rid::new(1),
        constant_list: Rid::new(1),
        ..LocalScopeRow::default()
    });
    builder
        .rows
        .state_machine_method
        .push(StateMachineMethodRow {
            move_next_method: Rid::new(3),
            kickoff_method: Rid::new(2),
        });
    written(&builder);
    let row = new_method(&mut builder, "Twice");
    let mut renumbering = MethodRenumbering::default();
    let token = builder
        .add_method(type_def(2), row, &[], &mut renumbering)
        .unwrap();
    assert_eq!(token, method_def(3));
    let rows = &builder.rows;
    assert_eq!(rows.method_debug_information.len(), 4);
    assert_eq!(
        rows.method_debug_information[2],
        MethodDebugInformationRow::default()
    );
    assert_eq!(rows.method_debug_information[3].document, Rid::new(1));
    assert_eq!(rows.local_scope[0].method, Rid::new(4));
    assert_eq!(rows.state_machine_method[0].move_next_method, Rid::new(4));
    assert_eq!(rows.state_machine_method[0].kickoff_method, Rid::new(2));
    let pdb = builder.pdb.as_ref().unwrap();
    assert_eq!(pdb.entry_point, method_def(4));
    assert_eq!(pdb.type_system_table_rows[TableId::MethodDef as usize], 4);
    written(&builder);
}

#[test]
fn a_new_metadata_root_with_every_addition_reads_back() {
    let mut builder = sorted_sample();
    let console = builder
        .add_assembly_ref("System.Console", [8, 0, 0, 0], &[], "")
        .unwrap();
    let class = builder.add_type_ref(console, "System", "Console").unwrap();
    let member = builder
        .add_member_ref(class, "WriteLine", &[0x00, 0x01, 0x01, 0x0E])
        .unwrap();
    let mut renumbering = MethodRenumbering::default();
    let row = new_method(&mut builder, "Twice");
    let twice = builder
        .add_method(type_def(2), row, &["value"], &mut renumbering)
        .unwrap();
    let locals = builder.add_stand_alone_sig(&[0x07, 0x01, 0x0E]).unwrap();
    let (bytes, rows) = written(&builder);
    // The root keeps its streams; a parse of the bytes and a second write
    // give the same bytes.
    let metadata = Metadata::parse(&bytes).unwrap();
    assert_eq!(
        MetadataBuilder::from_metadata(&metadata)
            .unwrap()
            .write()
            .unwrap(),
        bytes
    );
    let blobs = BlobHeap::new(metadata.blobs().data());
    assert_eq!(
        blobs
            .get(rows.stand_alone_sig[locals.row() as usize - 1].signature)
            .unwrap(),
        &[0x07, 0x01, 0x0E]
    );
    assert_eq!(rows.member_ref[member.row() as usize - 1].class, class);
    assert_eq!(
        metadata
            .strings()
            .get(rows.method_def[twice.row() as usize - 1].name)
            .unwrap(),
        "Twice"
    );
    assert_eq!(vec![twice], renumbering.added().collect::<Vec<_>>());
}

#[test]
fn a_removed_method_takes_its_parameters_and_the_later_methods_move_down() {
    let mut builder = sample();
    let before = builder.rows.clone();
    let row = new_method(&mut builder, "Twice");
    let mut renumbering = MethodRenumbering::default();
    let twice = builder
        .add_method(type_def(2), row, &["value"], &mut renumbering)
        .unwrap();
    assert_ne!(builder.rows.method_def, before.method_def);

    builder.remove_method(twice, &mut renumbering).unwrap();

    assert_eq!(builder.rows.method_def, before.method_def);
    assert_eq!(builder.rows.param, before.param);
    assert_eq!(builder.rows.type_def, before.type_def);
    for row in 1..=u32::try_from(before.method_def.len()).unwrap() {
        assert_eq!(renumbering.token(method_def(row)), method_def(row));
        assert!(!renumbering.is_removed(method_def(row)));
    }
    assert_eq!(renumbering.added().count(), 0, "the added method went");
    written(&builder);
}

#[test]
fn a_method_that_a_row_names_stays() {
    let mut builder = sorted_sample();
    let mut renumbering = MethodRenumbering::default();
    // An attribute of `Get` names it.
    assert!(
        builder
            .remove_method(method_def(3), &mut renumbering)
            .is_err()
    );
    assert!(
        builder
            .remove_method(method_def(99), &mut renumbering)
            .is_err()
    );
    assert!(
        builder
            .remove_method(type_def(1), &mut renumbering)
            .is_err()
    );
    assert_eq!(renumbering, MethodRenumbering::default());
}

#[test]
fn a_removed_generic_method_takes_its_instantiations_and_its_generic_parameters() {
    let mut builder = sorted_sample();
    let before = builder.rows.clone();
    let row = new_method(&mut builder, "Pick");
    let mut renumbering = MethodRenumbering::default();
    let pick = builder
        .add_method(type_def(2), row, &[], &mut renumbering)
        .unwrap();
    let name = builder.strings.add("T").unwrap();
    builder.rows.generic_param.push(GenericParamRow {
        number: 0,
        flags: 0,
        owner: pick,
        name,
    });
    builder.sort_tables().unwrap();
    let parameter = builder
        .rows
        .generic_param
        .iter()
        .position(|parameter| parameter.owner == pick)
        .unwrap();
    builder
        .rows
        .generic_param_constraint
        .push(GenericParamConstraintRow {
            owner: Rid::new(u32::try_from(parameter + 1).unwrap()),
            constraint: Token::new(TableId::TypeRef, 1),
        });
    builder.sort_tables().unwrap();
    let picked = builder.add_method_spec(pick, &[0x0A, 0x01, 0x08]).unwrap();
    let get = renumbering.token(method_def(3));
    let got = builder.add_method_spec(get, &[0x0A, 0x01, 0x0E]).unwrap();
    written(&builder);

    builder.remove_method(pick, &mut renumbering).unwrap();

    assert_eq!(builder.rows.method_def, before.method_def);
    assert_eq!(builder.rows.generic_param, before.generic_param);
    assert_eq!(
        builder.rows.generic_param_constraint,
        before.generic_param_constraint
    );
    // The instantiation of the sample stays first, and the one of `Get`
    // takes the row of the one of `Pick`.
    assert_eq!(builder.rows.method_spec.len(), before.method_spec.len() + 1);
    assert_eq!(
        builder.rows.method_spec[..before.method_spec.len()],
        before.method_spec[..]
    );
    assert_eq!(
        builder.rows.method_spec.last().unwrap().method,
        method_def(3)
    );
    assert!(renumbering.is_removed(picked));
    assert_eq!(renumbering.token(got), picked);
    written(&builder);
}

#[test]
fn the_references_of_a_method_name_each_column_that_holds_it() {
    let mut builder = sorted_sample();
    let spec = builder
        .add_method_spec(method_def(3), &[0x0A, 0x01, 0x08])
        .unwrap();
    let references = builder.references(TableId::MethodDef).unwrap();
    let of = |row: u32| -> alloc::vec::Vec<(TableId, &str)> {
        references
            .iter()
            .filter(|reference| reference.target == row)
            .map(|reference| (reference.table, reference.column))
            .collect()
    };
    // `Get` (row 3): the attribute on it and its instantiation.
    let get = of(3);
    assert!(
        get.contains(&(TableId::CustomAttribute, "parent")),
        "{get:?}"
    );
    assert!(get.contains(&(TableId::MethodSpec, "method")), "{get:?}");
    assert_eq!(
        spec.row(),
        u32::try_from(builder.rows.method_spec.len()).unwrap()
    );
    // The run of each type names its first method.
    let first = builder.rows.type_def[1].method_list.row();
    assert!(of(first).contains(&(TableId::TypeDef, "method_list")));
}

#[test]
fn a_generic_method_whose_instantiation_an_attribute_names_stays() {
    let mut builder = sorted_sample();
    let spec = builder
        .add_method_spec(method_def(3), &[0x0A, 0x01, 0x08])
        .unwrap();
    builder
        .rows
        .custom_attribute
        .retain(|row| row.parent != method_def(3));
    builder.rows.custom_attribute.push(CustomAttributeRow {
        parent: spec,
        attribute_type: Token::new(TableId::MemberRef, 1),
        value: BlobIndex(0),
    });
    builder.sort_tables().unwrap();
    let rows = builder.rows.clone();
    let mut renumbering = MethodRenumbering::default();
    assert!(
        builder
            .remove_method(method_def(3), &mut renumbering)
            .is_err()
    );
    assert_eq!(builder.rows, rows, "a refusal changes nothing");
    assert_eq!(renumbering, MethodRenumbering::default());
}

#[test]
fn a_method_of_the_sample_goes_and_the_rest_reads_back() {
    let mut builder = sample();
    let count = u32::try_from(builder.rows.method_def.len()).unwrap();
    let names: Vec<Vec<alloc::string::String>> = (0..builder.rows.type_def.len())
        .map(|index| {
            method_names(&builder, index)
                .into_iter()
                .map(alloc::string::String::from)
                .collect()
        })
        .collect();
    let mut renumbering = MethodRenumbering::default();
    builder
        .remove_method(method_def(1), &mut renumbering)
        .unwrap();

    assert_eq!(
        u32::try_from(builder.rows.method_def.len()).unwrap(),
        count - 1
    );
    assert!(renumbering.is_removed(method_def(1)));
    assert!(!renumbering.is_identity());
    for row in 2..=count {
        assert_eq!(renumbering.token(method_def(row)), method_def(row - 1));
    }
    // The type of the first method lost it; every other type keeps its
    // methods.
    let owner = names
        .iter()
        .position(|methods| !methods.is_empty())
        .unwrap();
    for (index, methods) in names.iter().enumerate() {
        let expected: Vec<&str> = methods
            .iter()
            .skip(usize::from(index == owner))
            .map(alloc::string::String::as_str)
            .collect();
        assert_eq!(method_names(&builder, index), expected);
    }
    written(&builder);
}
