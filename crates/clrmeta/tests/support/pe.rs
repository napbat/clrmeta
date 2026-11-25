//! The few PE structures that the tests need to find the metadata and the
//! method bodies of an assembly. clrmeta itself reads no PE files.

/// A PE file in memory.
pub struct PeFile {
    pub bytes: Vec<u8>,
    sections: Vec<Section>,
    cli_header: Option<(u32, u32)>,
}

struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

impl PeFile {
    /// Reads the headers. Returns `None` for a file that is not a PE file.
    pub fn parse(bytes: Vec<u8>) -> Option<Self> {
        if bytes.get(..2)? != b"MZ" {
            return None;
        }
        let pe = u32_at(&bytes, 0x3C)? as usize;
        if bytes.get(pe..pe + 4)? != b"PE\0\0" {
            return None;
        }
        let coff = pe + 4;
        let section_count = usize::from(u16_at(&bytes, coff + 2)?);
        let optional_size = usize::from(u16_at(&bytes, coff + 16)?);
        let optional = coff + 20;
        let directories = match u16_at(&bytes, optional)? {
            0x10B => optional + 96,
            0x20B => optional + 112,
            _ => return None,
        };
        let directory_count = u32_at(&bytes, directories - 4)?;
        let cli_header = if directory_count > 14 {
            let rva = u32_at(&bytes, directories + 14 * 8)?;
            let size = u32_at(&bytes, directories + 14 * 8 + 4)?;
            (rva != 0).then_some((rva, size))
        } else {
            None
        };
        let table = optional + optional_size;
        let sections = (0..section_count)
            .map(|index| {
                let at = table + index * 40;
                Some(Section {
                    virtual_size: u32_at(&bytes, at + 8)?,
                    virtual_address: u32_at(&bytes, at + 12)?,
                    raw_size: u32_at(&bytes, at + 16)?,
                    raw_offset: u32_at(&bytes, at + 20)?,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            bytes,
            sections,
            cli_header,
        })
    }

    /// Returns `len` bytes at a relative virtual address, from the raw data
    /// of its section.
    pub fn read(&self, rva: u32, len: usize) -> Option<&[u8]> {
        let section = self.sections.iter().find(|s| {
            rva >= s.virtual_address && rva - s.virtual_address < s.virtual_size.max(s.raw_size)
        })?;
        let delta = (rva - section.virtual_address) as usize;
        if delta + len > section.raw_size as usize {
            return None;
        }
        let start = section.raw_offset as usize + delta;
        self.bytes.get(start..start + len)
    }

    /// Returns the metadata bytes that the CLI header names, or `None` for
    /// a native image.
    pub fn metadata(&self) -> Option<&[u8]> {
        let (rva, size) = self.cli_header?;
        let header = self.read(rva, size.max(16) as usize)?;
        let metadata_rva = u32_at(header, 8)?;
        let metadata_size = u32_at(header, 12)?;
        self.read(metadata_rva, metadata_size as usize)
    }
}
