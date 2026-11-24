use alloc::vec;
use alloc::vec::Vec;

use clrmeta_model::TableId;

use super::*;

fn fat_body(code: &[u8], flags: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(flags | 0x3003).to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&u32::try_from(code.len()).unwrap().to_le_bytes());
    out.extend_from_slice(&0x1100_0002u32.to_le_bytes());
    out.extend_from_slice(code);
    out
}

#[test]
fn a_tiny_body_has_a_stack_of_eight_and_no_locals() {
    // ldc.i4.1; ret; then bytes of the next body.
    let bytes = [(2 << 2) | 0x2, 0x17, 0x2A, 0xFF];
    let body = MethodBody::parse(&bytes).unwrap();
    assert_eq!(body.format, HeaderFormat::Tiny);
    assert_eq!(body.code, &[0x17, 0x2A]);
    assert_eq!(body.max_stack, 8);
    assert!(body.local_var_sig.is_null());
    assert!(!body.init_locals());
    assert_eq!(body.size, 3);
    assert_eq!(body.encode().unwrap(), bytes[..3]);
}

#[test]
fn a_fat_body_reads_its_header_fields() {
    let bytes = fat_body(&[0x00, 0x2A], INIT_LOCALS);
    let body = MethodBody::parse(&bytes).unwrap();
    assert_eq!(body.format, HeaderFormat::Fat);
    assert_eq!(body.max_stack, 4);
    assert_eq!(body.local_var_sig, Token::new(TableId::StandAloneSig, 2));
    assert!(body.init_locals());
    assert_eq!(body.code_offset(), 12);
    assert_eq!(body.code, &[0x00, 0x2A]);
    assert_eq!(body.encode().unwrap(), bytes);
}

#[test]
fn small_and_fat_clauses_of_every_kind_read_and_write() {
    let code = [0u8; 40];
    let mut bytes = fat_body(&code, MORE_SECTS);
    // A small section with a catch and a finally, then a fat section with a
    // filter and a fault.
    bytes.extend_from_slice(&[SECTION_EH_TABLE | SECTION_MORE_SECTS, 4 + 24, 0, 0]);
    for (flags, operand) in [(0u16, 0x0100_0005u32), (2, 0)] {
        bytes.extend_from_slice(&flags.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.push(4);
        bytes.extend_from_slice(&5u16.to_le_bytes());
        bytes.push(3);
        bytes.extend_from_slice(&operand.to_le_bytes());
    }
    bytes.extend_from_slice(&[SECTION_EH_TABLE | SECTION_FAT_FORMAT, 4 + 48, 0, 0]);
    for (flags, handler, operand) in [(1u32, 20u32, 10u32), (4, 30, 0)] {
        for value in [flags, 8, 2, handler, 10, operand] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
    }
    bytes.extend_from_slice(&[0xEE; 8]);
    let body = MethodBody::parse(&bytes).unwrap();
    assert_eq!(body.size, bytes.len() - 8);
    let kinds: Vec<_> = body.clauses.iter().map(|c| c.kind).collect();
    assert_eq!(
        kinds,
        [
            ExceptionClauseKind::Catch(Token(0x0100_0005)),
            ExceptionClauseKind::Finally,
            ExceptionClauseKind::Filter(10),
            ExceptionClauseKind::Fault,
        ]
    );
    assert_eq!(body.clauses[0].try_range, 1..5);
    assert_eq!(body.clauses[0].handler_range, 5..8);
    assert_eq!(body.clauses[2].filter_range(), Some(10..20));
    assert_eq!(
        body.sections,
        [
            DataSection::ExceptionClauses {
                fat: false,
                count: 2
            },
            DataSection::ExceptionClauses {
                fat: true,
                count: 2
            },
        ]
    );
    assert_eq!(body.encode().unwrap(), bytes[..body.size]);

    let read = |rva: u32, len: usize| {
        let start = usize::try_from(rva).ok()? - 0x1000;
        bytes.get(start..start + len)
    };
    assert_eq!(MethodBody::at_rva(0x1000, read).unwrap(), body);
    assert!(MethodBody::at_rva(0x1000, |_, _| None).is_err());
}

#[test]
fn a_body_without_sections_gets_one_section_for_its_clauses() {
    let code = [0u8; 300];
    let body = MethodBody {
        format: HeaderFormat::Fat,
        flags: FAT_FORMAT,
        header_size: 12,
        max_stack: 1,
        local_var_sig: Token::NULL,
        code: &code,
        clauses: vec![ExceptionClause {
            kind: ExceptionClauseKind::Fault,
            try_range: 0..290,
            handler_range: 290..300,
        }],
        sections: Vec::new(),
        size: 0,
    };
    let encoded = body.encode().unwrap();
    let parsed = MethodBody::parse(&encoded).unwrap();
    assert_eq!(parsed.clauses, body.clauses);
    assert_eq!(
        parsed.sections,
        [DataSection::ExceptionClauses {
            fat: true,
            count: 1
        }]
    );
}

#[test]
fn malformed_bodies_are_errors() {
    // Neither tiny nor fat.
    assert!(MethodBody::parse(&[0x00]).is_err());
    // Code past the end.
    assert!(MethodBody::parse(&[(5 << 2) | 0x2, 0x00]).is_err());
    // A fat header shorter than 12 bytes.
    assert!(MethodBody::parse(&[0x03, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    // A clause outside the code.
    let mut bytes = fat_body(&[0x2A], MORE_SECTS);
    bytes.extend_from_slice(&[0x00; 3]);
    bytes.extend_from_slice(&[
        SECTION_EH_TABLE,
        16,
        0,
        0,
        2,
        0,
        0,
        0,
        1,
        1,
        0,
        1,
        0,
        0,
        0,
        0,
    ]);
    assert!(matches!(
        MethodBody::parse(&bytes),
        Err(Error::Malformed { .. })
    ));
    // A clause with flags that name no kind.
    let mut bytes = fat_body(&[0x2A], MORE_SECTS);
    bytes.extend_from_slice(&[0x00; 3]);
    bytes.extend_from_slice(&[
        SECTION_EH_TABLE,
        16,
        0,
        0,
        3,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]);
    assert!(MethodBody::parse(&bytes).is_err());
    // A tiny header that cannot hold its body.
    let mut body = MethodBody::parse(&[0x06, 0x2A]).unwrap();
    body.max_stack = 9;
    assert!(body.encode().is_err());
}
