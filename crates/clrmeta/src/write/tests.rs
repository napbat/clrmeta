use crate::heaps::Guid;
use crate::metadata::Metadata;
use crate::pdb::PdbStream;
use crate::tables::{
    DocumentRow, HEAP_STRINGS_WIDE, MethodDebugInformationRow, TableId, TypeDefRow, TypeRefRow,
};
use crate::test_support::sample;
use crate::token::{Rid, Token};
use crate::write::{MetadataBuilder, StreamSlot};

#[test]
fn a_written_module_reads_back_and_writes_the_same_bytes() {
    let bytes = sample().write().unwrap();
    let md = Metadata::parse(&bytes).unwrap();
    let again = MetadataBuilder::from_metadata(&md)
        .unwrap()
        .write()
        .unwrap();
    assert_eq!(again, bytes);
    let copy = Metadata::parse(&again).unwrap();
    assert_eq!(
        copy.tables().to_rows().unwrap(),
        md.tables().to_rows().unwrap()
    );
}

#[test]
fn the_widths_grow_with_the_heaps_and_the_tables() {
    let mut builder = sample();
    for row in 0..70_000u32 {
        let name = builder.strings.add(&alloc::format!("T{row}")).unwrap();
        builder.rows.type_ref.push(TypeRefRow {
            resolution_scope: Token::new(TableId::AssemblyRef, 1),
            type_name: name,
            type_namespace: crate::heaps::StringIndex(0),
        });
    }
    let bytes = builder.write().unwrap();
    let md = Metadata::parse(&bytes).unwrap();
    let header = md.tables().header();
    assert_ne!(header.heap_sizes & HEAP_STRINGS_WIDE, 0);
    assert_eq!(header.row_count(TableId::TypeRef), 70_002);
    // MemberRefParent has 3 tag bits: 70 002 rows need a 4-byte index.
    assert_eq!(md.tables().layout().table(TableId::MemberRef).widths[0], 4);
    let last = md.tables().row(Rid::<TypeRefRow>::new(70_002)).unwrap();
    assert_eq!(md.strings().get(last.type_name).unwrap(), "T69999");
    assert_eq!(md.validate(), []);
}

#[test]
fn unoptimized_metadata_with_pointer_tables_reads_through_the_pointers() {
    let mut builder = sample();
    builder.uncompressed = true;
    // The fields of the types in reverse order through FieldPtr.
    for field in [3, 2, 1] {
        builder.rows.field_ptr.push(crate::tables::FieldPtrRow {
            field: Rid::new(field),
        });
    }
    let bytes = builder.write().unwrap();
    let md = Metadata::parse(&bytes).unwrap();
    assert_eq!(md.tables_stream_name(), b"#-");
    let fields: alloc::vec::Vec<u32> = md
        .fields_of(Rid::<TypeDefRow>::new(2))
        .unwrap()
        .map(Rid::row)
        .collect();
    assert_eq!(fields, [3]);
    assert_eq!(md.field_owner(Rid::new(1)), Some(Rid::new(4)));
    let again = MetadataBuilder::from_metadata(&md)
        .unwrap()
        .write()
        .unwrap();
    assert_eq!(again, bytes);
}

#[test]
fn a_portable_pdb_sizes_its_indices_from_the_type_system_rows() {
    let mut builder = MetadataBuilder::new("PDB v1.0");
    let mut rows = [0; 64];
    rows[TableId::MethodDef as usize] = 70_000;
    builder.pdb = Some(PdbStream {
        id: [1; 20],
        entry_point: Token::NULL,
        referenced_type_system_tables: 1 << TableId::MethodDef as u8,
        type_system_table_rows: rows,
    });
    builder.streams.insert(0, StreamSlot::Pdb);
    let language = builder.guids.add(Guid([9; 16])).unwrap();
    builder.rows.document.push(DocumentRow {
        language,
        ..DocumentRow::default()
    });
    builder
        .rows
        .method_debug_information
        .push(MethodDebugInformationRow {
            document: Rid::new(1),
            ..MethodDebugInformationRow::default()
        });
    builder.rows.local_scope.push(crate::tables::LocalScopeRow {
        method: Rid::new(69_999),
        variable_list: Rid::new(1),
        constant_list: Rid::new(1),
        ..crate::tables::LocalScopeRow::default()
    });
    let bytes = builder.write().unwrap();
    let md = Metadata::parse(&bytes).unwrap();
    assert_eq!(md.pdb().unwrap().row_count(TableId::MethodDef), 70_000);
    assert_eq!(md.tables().layout().table(TableId::LocalScope).widths[0], 4);
    let scope = md
        .tables()
        .row(Rid::<crate::tables::LocalScopeRow>::new(1))
        .unwrap();
    assert_eq!(scope.method.row(), 69_999);
    assert_eq!(md.guids().get(language).unwrap(), Some(Guid([9; 16])));
    assert_eq!(
        MetadataBuilder::from_metadata(&md)
            .unwrap()
            .write()
            .unwrap(),
        bytes
    );
}

#[test]
fn a_value_that_does_not_fit_its_column_is_an_error() {
    let mut builder = sample();
    builder.rows.type_def[0].extends = Token::new(TableId::MethodDef, 1);
    assert!(matches!(
        builder.write(),
        Err(crate::Error::Column {
            table: TableId::TypeDef,
            row: 1,
            column: "extends",
            ..
        })
    ));
    let mut builder = sample();
    builder.rows.type_def[0].type_name = crate::heaps::StringIndex(0x1_0000);
    assert!(builder.write().is_err());
}
