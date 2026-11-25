//! The validation of a method body against ECMA-335 II.25.4: what the
//! parser accepts because the runtime accepts it, or because only the JIT
//! rejects it when it compiles the method.

use alloc::vec::Vec;

use crate::body::sections::{FAT_CLAUSE, SMALL_CLAUSE, SectionHeader, clause_fields};
use crate::body::{
    DataSection, ExceptionClause, ExceptionClauseKind, FAT_FORMAT, HeaderFormat, INIT_LOCALS,
    MORE_SECTS, MethodBody, SECTION_EH_TABLE, SECTION_KIND_MASK,
};
use crate::error::Error;
use crate::tables::TableId;

/// The largest number of clauses that the JIT compiles (`CoreCLR`
/// `MAX_XCPTN_INDEX`). The runtime passes the count to the JIT in 16 bits.
const MAX_CLAUSES: usize = 0xFFFE;

/// The flags of the four kinds of clauses.
const CLAUSE_KINDS: [u32; 4] = [
    ExceptionClauseKind::FLAG_EXCEPTION,
    ExceptionClauseKind::FLAG_FILTER,
    ExceptionClauseKind::FLAG_FINALLY,
    ExceptionClauseKind::FLAG_FAULT,
];

const fn issue(offset: usize, reason: &'static str) -> Error {
    Error::Malformed {
        structure: "method body",
        offset,
        reason,
    }
}

impl MethodBody<'_> {
    /// Checks the body against ECMA-335 II.25.4 and returns the problems in
    /// body order. Each error is [`Error::Malformed`] with the offset from
    /// the first byte of the header.
    ///
    /// The checks cover what [`MethodBody::parse`] accepts: a fat header of
    /// more than 3 dwords or with unknown flags, a local variable token of
    /// another table, a section of clauses whose `DataSize` leaves out the
    /// header, clause flags that name no single kind, sections whose
    /// clauses the runtime does not read, and clauses that the JIT rejects
    /// (an empty block, a block outside the code, a filter that does not
    /// start before its handler), and a clause count that the runtime cuts
    /// to 16 bits. [`MethodBody::validate_at`] also checks the place of the
    /// header.
    #[must_use]
    pub fn validate(&self) -> Vec<Error> {
        let mut issues = Vec::new();
        if self.format == HeaderFormat::Fat {
            if self.header_size != 12 {
                issues.push(issue(0, "the fat header is not 12 bytes long"));
            }
            if self.flags & !(FAT_FORMAT | MORE_SECTS | INIT_LOCALS) != 0 {
                issues.push(issue(
                    0,
                    "the header has flags that ECMA-335 does not define",
                ));
            }
        }
        let locals = self.local_var_sig;
        if !locals.is_null() && locals.table() != Some(TableId::StandAloneSig) {
            issues.push(issue(
                8,
                "the local variable token is not a StandAloneSig token",
            ));
        }
        self.validate_sections(&mut issues);
        let code_size = u32::try_from(self.code.len()).unwrap_or(u32::MAX);
        for (position, clause) in self.clauses.iter().enumerate() {
            let offset = self.clause_offset(position);
            for reason in clause_problems(clause, code_size) {
                issues.push(issue(offset, reason));
            }
        }
        if self.clauses.len() > 0xFFFF {
            issues.push(issue(
                0,
                "the runtime passes the clause count to the JIT in 16 bits, so the JIT sees fewer clauses",
            ));
        }
        if self.clauses.len() > MAX_CLAUSES {
            issues.push(issue(0, "the JIT does not compile more than 65534 clauses"));
        }
        issues
    }

    /// Checks the body as [`MethodBody::validate`] does, and the place of the
    /// body at a relative virtual address: the 64-bit runtime rejects a fat
    /// header that does not start at a multiple of 4 ("Bad IL range",
    /// `CoreCLR` `CheckILMethod`), which the parser reads.
    #[must_use]
    pub fn validate_at(&self, rva: u32) -> Vec<Error> {
        let mut issues = Vec::new();
        if self.format == HeaderFormat::Fat && !rva.is_multiple_of(4) {
            issues.push(issue(
                0,
                "the fat header does not start at a multiple of 4; the 64-bit runtime rejects the method",
            ));
        }
        issues.extend(self.validate());
        issues
    }

    /// Returns the offset of each section from the first byte of the
    /// header.
    fn section_offsets(&self) -> impl Iterator<Item = usize> + '_ {
        let mut next = (self.header_size + self.code.len()).next_multiple_of(4);
        self.sections.iter().map(move |section| {
            let start = next;
            let size = match section {
                DataSection::ExceptionClauses { raw, .. } => raw.len().max(4),
                DataSection::Other { data, .. } => 4 + data.len(),
            };
            next = (start + size).next_multiple_of(4);
            start
        })
    }

    /// Returns the offset of a clause of [`MethodBody::clauses`], or 0 when
    /// no section of the body holds it.
    fn clause_offset(&self, position: usize) -> usize {
        let mut before = 0;
        for (section, start) in self.sections.iter().zip(self.section_offsets()) {
            if let DataSection::ExceptionClauses { fat, count, .. } = *section {
                if position < before + count {
                    let size = if fat { FAT_CLAUSE } else { SMALL_CLAUSE };
                    return start + 4 + (position - before) * size;
                }
                before += count;
            }
        }
        0
    }

    fn validate_sections(&self, issues: &mut Vec<Error>) {
        let sections = self.sections.iter().zip(self.section_offsets());
        for (index, (section, start)) in sections.enumerate() {
            match *section {
                DataSection::ExceptionClauses { fat, count, raw } => {
                    if index > 0 {
                        issues.push(issue(
                            start,
                            "the runtime reads clauses only from the first section",
                        ));
                    }
                    let Some(header) = raw.first_chunk::<4>().copied().map(SectionHeader::read)
                    else {
                        continue;
                    };
                    let size = if fat { FAT_CLAUSE } else { SMALL_CLAUSE };
                    if header.data_size != 4 + count * size {
                        issues.push(issue(
                            start,
                            "DataSize is not the size of the section header and its clauses",
                        ));
                    }
                    let clauses = raw.get(4..).unwrap_or_default();
                    for (position, clause) in clauses.chunks_exact(size).enumerate() {
                        let [flags, ..] = clause_fields(clause, fat);
                        if !CLAUSE_KINDS.contains(&flags) {
                            issues.push(issue(
                                start + 4 + position * size,
                                "the clause flags are not the flags of one kind",
                            ));
                        }
                    }
                }
                DataSection::Other { kind, .. } => {
                    let reason = if kind & SECTION_KIND_MASK == SECTION_EH_TABLE {
                        "the runtime reads clauses only from the first section"
                    } else if kind & SECTION_EH_TABLE != 0 {
                        "the section kind adds other bits to the clause bit; the runtime does not read its clauses"
                    } else {
                        "the runtime ignores a section of this kind"
                    };
                    issues.push(issue(start, reason));
                }
            }
        }
    }
}

/// Returns the problems of a clause that the JIT rejects (`CoreCLR`
/// `fgFindBasicBlocks` and `verInsertEhNodeInTree`).
fn clause_problems(clause: &ExceptionClause, code_size: u32) -> Vec<&'static str> {
    let mut problems = Vec::new();
    for range in [&clause.try_range, &clause.handler_range] {
        if range.end < range.start {
            problems.push("a block ends past 4 GiB");
        } else if range.is_empty() {
            problems.push("a block is empty");
        } else if range.end > code_size {
            problems.push("a block ends after the code");
        }
    }
    if clause.handler_range.start == 0 {
        problems.push("the handler starts at the first instruction of the method");
    }
    if let ExceptionClauseKind::Filter(start) = clause.kind {
        if start == 0 {
            problems.push("the filter starts at the first instruction of the method");
        }
        if start >= clause.handler_range.start {
            problems.push("the filter does not start before its handler");
        }
    }
    problems
}
