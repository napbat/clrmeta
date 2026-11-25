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

/// Appends a small clause.
fn small_clause(out: &mut Vec<u8>, flags: u16, blocks: [u16; 4], operand: u32) {
    let [try_offset, try_length, handler_offset, handler_length] = blocks;
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&try_offset.to_le_bytes());
    out.push(u8::try_from(try_length).unwrap());
    out.extend_from_slice(&handler_offset.to_le_bytes());
    out.push(u8::try_from(handler_length).unwrap());
    out.extend_from_slice(&operand.to_le_bytes());
}

/// A fat body of 16 bytes of code with a catch and a finally in one small
/// section whose kind byte and `DataSize` the caller chooses, padded to
/// the section.
fn body_with_section(kind: u8, data_size: u8) -> Vec<u8> {
    let mut bytes = fat_body(&[0; 16], MORE_SECTS);
    bytes.extend_from_slice(&[kind, data_size, 0, 0]);
    small_clause(&mut bytes, 0, [1, 4, 5, 3], 0x0100_0005);
    small_clause(&mut bytes, 2, [1, 8, 9, 2], 0);
    bytes
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
    assert_eq!(body.validate(), []);
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
    assert_eq!(body.validate(), []);
}

#[test]
fn small_and_fat_clauses_of_every_kind_read_and_write() {
    let code = [0u8; 40];
    let mut bytes = fat_body(&code, MORE_SECTS);
    // A small section with a catch and a finally, then a fat section with a
    // filter and a fault.
    bytes.extend_from_slice(&[SECTION_EH_TABLE | SECTION_MORE_SECTS, 4 + 24, 0, 0]);
    small_clause(&mut bytes, 0, [1, 4, 5, 3], 0x0100_0005);
    small_clause(&mut bytes, 2, [1, 4, 5, 3], 0);
    let fat_start = bytes.len();
    bytes.extend_from_slice(&[SECTION_EH_TABLE | SECTION_FAT_FORMAT, 4 + 48, 0, 0]);
    for (flags, handler, operand) in [(1u32, 20u32, 10u32), (4, 30, 0)] {
        for value in [flags, 8, 2, handler, 10, operand] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
    }
    bytes.extend_from_slice(&[0xEE; 8]);
    let body = MethodBody::parse(&bytes).unwrap();
    assert_eq!(body.size, bytes.len() - 8);
    // The runtime reads the clauses of the first section only.
    let kinds: Vec<_> = body.clauses.iter().map(|c| c.kind).collect();
    assert_eq!(
        kinds,
        [
            ExceptionClauseKind::Catch(Token(0x0100_0005)),
            ExceptionClauseKind::Finally,
        ]
    );
    assert_eq!(body.clauses[0].try_range, 1..5);
    assert_eq!(body.clauses[0].handler_range, 5..8);
    assert_eq!(
        body.sections,
        [
            DataSection::ExceptionClauses {
                fat: false,
                count: 2,
                raw: &bytes[52..80],
            },
            DataSection::Other {
                kind: SECTION_EH_TABLE | SECTION_FAT_FORMAT,
                data: &bytes[fat_start + 4..bytes.len() - 8],
            },
        ]
    );
    assert_eq!(body.encode().unwrap(), bytes[..body.size]);
    let issues = body.validate();
    assert_eq!(issues.len(), 1);
    assert!(matches!(issues[0], Error::Malformed { offset, .. } if offset == fat_start));

    let read = |rva: u32, len: usize| {
        let start = usize::try_from(rva).ok()? - 0x1000;
        bytes.get(start..start + len)
    };
    assert_eq!(MethodBody::at_rva(0x1000, read).unwrap(), body);
    assert!(MethodBody::at_rva(0x1000, |_, _| None).is_err());
}

#[test]
fn a_fat_section_of_clauses_reads_every_kind() {
    let mut bytes = fat_body(&[0; 40], MORE_SECTS);
    bytes.extend_from_slice(&[SECTION_EH_TABLE | SECTION_FAT_FORMAT, 4 + 48, 0, 0]);
    for (flags, handler, operand) in [(1u32, 20u32, 10u32), (4, 30, 0)] {
        for value in [flags, 8, 2, handler, 10, operand] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
    }
    let body = MethodBody::parse(&bytes).unwrap();
    let kinds: Vec<_> = body.clauses.iter().map(|c| c.kind).collect();
    assert_eq!(
        kinds,
        [ExceptionClauseKind::Filter(10), ExceptionClauseKind::Fault]
    );
    assert_eq!(body.clauses[0].filter_range(), Some(10..20));
    assert_eq!(body.encode().unwrap(), bytes);
    assert_eq!(body.validate(), []);
}

#[test]
fn a_body_without_sections_gets_one_section_for_its_clauses() {
    let code = [0u8; 300];
    let body = MethodBody {
        format: HeaderFormat::Fat,
        flags: FAT_FORMAT,
        header_size: 12,
        extra_header: &[],
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
    assert!(matches!(
        parsed.sections[..],
        [DataSection::ExceptionClauses {
            fat: true,
            count: 1,
            ..
        }]
    ));
}

#[test]
fn malformed_bodies_are_errors() {
    // Neither tiny nor fat.
    assert!(MethodBody::parse(&[0x00]).is_err());
    // Code past the end.
    assert!(MethodBody::parse(&[(5 << 2) | 0x2, 0x00]).is_err());
    // A fat header shorter than 12 bytes.
    assert!(MethodBody::parse(&[0x03, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    // A tiny header that cannot hold its body.
    let mut body = MethodBody::parse(&[0x06, 0x2A]).unwrap();
    body.max_stack = 9;
    assert!(body.encode().is_err());
}

#[test]
fn a_first_byte_with_the_low_bits_7_is_not_a_fat_header() {
    // CoreCLR and .NET Framework throw "Bad IL range" for this header.
    let bytes = fat_body(&[0x2A], 0x4);
    assert_eq!(bytes[0] & 0x7, 0x7);
    assert!(MethodBody::parse(&bytes).is_err());
}

#[test]
fn a_fat_header_of_more_dwords_and_unknown_flags_reads() {
    // The runtime runs a body with a header of 4 dwords and the flags
    // 0x900.
    let mut bytes = fat_body(&[0x2A], 0x900);
    bytes[1] = (bytes[1] & 0x0F) | 0x40;
    // The extra dword holds junk, which the encoder keeps.
    bytes.splice(12..12, [0xAA, 0xBB, 0xCC, 0xDD]);
    let body = MethodBody::parse(&bytes).unwrap();
    assert_eq!(body.header_size, 16);
    assert_eq!(body.extra_header, &[0xAA, 0xBB, 0xCC, 0xDD]);
    assert_eq!(body.code, &[0x2A]);
    assert_eq!(body.encode().unwrap(), bytes);
    // Fewer extra bytes than the header holds: the encoder adds zeros; more
    // bytes than it holds is an error.
    let mut short = body.clone();
    short.extra_header = &[0xAA];
    assert_eq!(short.encode().unwrap()[12..16], [0xAA, 0, 0, 0]);
    let mut long = body.clone();
    long.extra_header = &[0; 5];
    assert!(long.encode().is_err());
    let reasons: Vec<_> = body.validate().iter().map(reason).collect();
    assert_eq!(
        reasons,
        [
            "the fat header is not 12 bytes long",
            "the header has flags that ECMA-335 does not define"
        ]
    );
}

#[test]
fn an_unaligned_fat_header_reads_and_is_reported_at_its_rva() {
    // The 64-bit runtime throws "Bad IL range" for a fat header at an RVA
    // that is not a multiple of 4; the parser reads it.
    let mut image = vec![0xEE; 2];
    image.extend(fat_body(&[0x2A], 0));
    let read = |rva: u32, len: usize| image.get(usize::try_from(rva).ok()?..)?.get(..len);
    let body = MethodBody::at_rva(2, read).unwrap();
    assert_eq!(body.code, &[0x2A]);
    assert_eq!(body.validate(), []);
    let reasons: Vec<_> = body.validate_at(2).iter().map(reason).collect();
    assert_eq!(
        reasons,
        ["the fat header does not start at a multiple of 4; the 64-bit runtime rejects the method"]
    );
    assert_eq!(body.validate_at(4), []);
    // A tiny header can start anywhere.
    let tiny = MethodBody::parse(&[(1 << 2) | 0x2, 0x2A]).unwrap();
    assert_eq!(tiny.validate_at(3), []);
}

#[test]
fn a_clause_count_past_16_bits_reads_and_is_reported() {
    // The runtime passes the count to the JIT in 16 bits: 65 537 clauses
    // reach the JIT as 1.
    let count = 0x1_0001;
    let mut bytes = fat_body(&[0; 16], MORE_SECTS);
    let size = u32::try_from(4 + count * 24).unwrap().to_le_bytes();
    bytes.extend_from_slice(&[
        SECTION_EH_TABLE | SECTION_FAT_FORMAT,
        size[0],
        size[1],
        size[2],
    ]);
    for _ in 0..count {
        for value in [2u32, 1, 4, 8, 4, 0] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
    }
    let body = MethodBody::parse(&bytes).unwrap();
    assert_eq!(body.clauses.len(), count);
    let reasons: Vec<_> = body.validate().iter().map(reason).collect();
    assert_eq!(
        reasons,
        [
            "the runtime passes the clause count to the JIT in 16 bits, so the JIT sees fewer clauses",
            "the JIT does not compile more than 65534 clauses"
        ]
    );
    assert_eq!(body.encode().unwrap(), bytes);
}

fn reason(error: &Error) -> &'static str {
    match *error {
        Error::Malformed { reason, .. } => reason,
        _ => "",
    }
}

#[test]
fn a_section_size_that_leaves_out_the_header_still_holds_its_clauses() {
    // VB and MC++ wrote DataSize without the 4 bytes of the header; the
    // runtime counts DataSize / 12 clauses and catches both.
    for data_size in [24, 28, 35] {
        let bytes = body_with_section(SECTION_EH_TABLE, data_size);
        let body = MethodBody::parse(&bytes).unwrap();
        assert_eq!(body.clauses.len(), 2, "{data_size}");
        assert_eq!(body.size, bytes.len());
        let read = |rva: u32, len: usize| bytes.get(usize::try_from(rva).ok()?..)?.get(..len);
        assert_eq!(MethodBody::at_rva(0, read).unwrap(), body);
        let canonical = data_size == 28;
        assert_eq!(body.validate().is_empty(), canonical, "{data_size}");
    }
    // DataSize 12 holds one clause, and 4 holds none.
    let one = body_with_section(SECTION_EH_TABLE, 12);
    assert_eq!(MethodBody::parse(&one).unwrap().clauses.len(), 1);
    let none = body_with_section(SECTION_EH_TABLE, 4);
    assert_eq!(MethodBody::parse(&none).unwrap().clauses, []);
}

#[test]
fn a_section_kind_with_other_bits_holds_no_clauses_for_the_runtime() {
    // The runtime lets the exception escape for the kinds 0x03 and 0x21.
    for kind in [
        SECTION_EH_TABLE | SECTION_OPT_IL_TABLE,
        SECTION_EH_TABLE | 0x20,
    ] {
        let bytes = body_with_section(kind, 28);
        let body = MethodBody::parse(&bytes).unwrap();
        assert_eq!(body.clauses, []);
        assert!(matches!(body.sections[..], [DataSection::Other { kind: k, .. }] if k == kind));
        assert_eq!(body.encode().unwrap(), bytes);
        assert_eq!(body.validate().len(), 1);
    }
}

#[test]
fn clauses_after_an_unknown_first_section_are_not_read() {
    // A first section of kind 0x02 hides the clauses from the runtime.
    let mut bytes = fat_body(&[0; 16], MORE_SECTS);
    bytes.extend_from_slice(&[SECTION_OPT_IL_TABLE | SECTION_MORE_SECTS, 4, 0, 0]);
    bytes.extend_from_slice(&[SECTION_EH_TABLE, 16, 0, 0]);
    small_clause(&mut bytes, 0, [1, 4, 5, 3], 0x0100_0005);
    let body = MethodBody::parse(&bytes).unwrap();
    assert_eq!(body.clauses, []);
    assert_eq!(body.sections.len(), 2);
    assert_eq!(body.size, bytes.len());
    assert_eq!(body.encode().unwrap(), bytes);
    assert_eq!(body.validate().len(), 2);
    // An unknown section after the clauses changes nothing.
    let mut after = body_with_section(SECTION_EH_TABLE | SECTION_MORE_SECTS, 28);
    after.extend_from_slice(&[SECTION_OPT_IL_TABLE, 8, 0, 0, 1, 2, 3, 4]);
    let body = MethodBody::parse(&after).unwrap();
    assert_eq!(body.clauses.len(), 2);
    assert_eq!(body.encode().unwrap(), after);
}

#[test]
fn a_section_of_size_zero_is_an_error_and_a_short_one_holds_its_header() {
    // The runtime rejects a section whose DataSize is 0, which would loop.
    let mut bytes = fat_body(&[0; 16], MORE_SECTS);
    bytes.extend_from_slice(&[SECTION_OPT_IL_TABLE | SECTION_MORE_SECTS, 0, 0, 0]);
    bytes.extend_from_slice(&[0; 8]);
    assert!(MethodBody::parse(&bytes).is_err());
    let read = |rva: u32, len: usize| bytes.get(usize::try_from(rva).ok()?..)?.get(..len);
    assert!(MethodBody::at_rva(0, read).is_err());
    // A DataSize of 2 still takes the 4 bytes of the header.
    let mut short = fat_body(&[0; 16], MORE_SECTS);
    short.extend_from_slice(&[SECTION_OPT_IL_TABLE, 2, 0, 0]);
    let body = MethodBody::parse(&short).unwrap();
    assert_eq!(body.size, short.len());
    let read = |rva: u32, len: usize| short.get(usize::try_from(rva).ok()?..)?.get(..len);
    assert_eq!(MethodBody::at_rva(0, read).unwrap(), body);
}

#[test]
fn clause_flags_follow_the_bits_that_the_jit_tests() {
    // Unknown bits (0x8, 0x20) leave a catch; the runtime runs them as
    // catch clauses. 0x6 is a fault for the JIT.
    for (flags, kind) in [
        (0x8, ExceptionClauseKind::Catch(Token(7))),
        (0x20, ExceptionClauseKind::Catch(Token(7))),
        (0x6, ExceptionClauseKind::Fault),
        (0x3, ExceptionClauseKind::Finally),
        (0x9, ExceptionClauseKind::Filter(7)),
    ] {
        let mut bytes = fat_body(&[0; 16], MORE_SECTS);
        bytes.extend_from_slice(&[SECTION_EH_TABLE, 16, 0, 0]);
        small_clause(&mut bytes, flags, [1, 4, 8, 3], 7);
        let body = MethodBody::parse(&bytes).unwrap();
        assert_eq!(body.clauses[0].kind, kind, "{flags:#x}");
        let reasons: Vec<_> = body.validate().iter().map(reason).collect();
        assert!(reasons.contains(&"the clause flags are not the flags of one kind"));
    }
}

#[test]
fn a_clause_that_the_jit_rejects_reads_and_validates_with_problems() {
    // The JIT throws InvalidProgramException for a handler past the code;
    // the body itself loads.
    let mut bytes = fat_body(&[0; 16], MORE_SECTS);
    bytes.extend_from_slice(&[SECTION_EH_TABLE | SECTION_FAT_FORMAT, 4 + 48, 0, 0]);
    for value in [0u32, 4, 0, 0xFFFF_FFF0, 0x20, 0x0100_0001] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    for value in [1u32, 1, 2, 3, 4, 9] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    let body = MethodBody::parse(&bytes).unwrap();
    assert_eq!(body.clauses.len(), 2);
    let handler = &body.clauses[0].handler_range;
    assert_eq!((handler.start, handler.end), (0xFFFF_FFF0, 0x10));
    let reasons: Vec<_> = body.validate().iter().map(reason).collect();
    assert_eq!(
        reasons,
        [
            "a block is empty",
            "a block ends past 4 GiB",
            "the filter does not start before its handler",
        ]
    );
}

#[test]
fn a_local_token_of_another_table_is_reported() {
    let mut bytes = fat_body(&[0x2A], 0);
    bytes[8..12].copy_from_slice(&0x0200_0001u32.to_le_bytes());
    let body = MethodBody::parse(&bytes).unwrap();
    let reasons: Vec<_> = body.validate().iter().map(reason).collect();
    assert_eq!(
        reasons,
        ["the local variable token is not a StandAloneSig token"]
    );
}
