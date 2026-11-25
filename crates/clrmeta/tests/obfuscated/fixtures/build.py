"""Builds the obfuscated and malformed fixtures of the `obfuscated` tests.

Run it on Windows from this directory: `python build.py`. It needs:

- the C# compiler of .NET Framework 4 (`csc.exe`, part of Windows),
- the .NET SDK or runtime (`dotnet`) to run the fixtures on CoreCLR,
- the network once, to download ConfuserEx 1.6.0 (MIT) from GitHub.

The script compiles `Sample.cs`, obfuscates it with ConfuserEx, and patches
the metadata and the method bodies of the sample to make each quirk that the
.NET runtime loads although ECMA-335 does not allow it. It then runs every
fixture on CoreCLR and on .NET Framework and checks the output that the
fixture expects, so each fixture is proof of what the runtime reads. The
output of the runs goes to `runs.txt`.
"""

import os
import shutil
import struct
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
CSC = os.path.join(os.environ.get("WINDIR", "C:/Windows"),
                   "Microsoft.NET/Framework64/v4.0.30319/csc.exe")
CONFUSER_URL = ("https://github.com/mkaring/ConfuserEx/releases/download/v1.6.0/"
                "ConfuserEx-CLI.zip")
CACHE = os.path.join(tempfile.gettempdir(), "clrmeta-fixtures")
RUNTIME_CONFIG = ('{ "runtimeOptions": { "tfm": "net8.0", "rollForward": "LatestMajor", '
                  '"framework": { "name": "Microsoft.NETCore.App", "version": "8.0.0" } } }')

# The coded index kinds (II.24.2.6): tag bits and the table of each tag.
CODED = {
    "TypeDefOrRef": (2, [2, 1, 0x1B]),
    "HasConstant": (2, [4, 8, 0x17]),
    "HasCustomAttribute": (5, [6, 4, 1, 2, 8, 9, 10, 0, 14, 0x17, 0x14, 0x11, 0x1A, 0x1B,
                               0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B]),
    "HasFieldMarshal": (1, [4, 8]),
    "HasDeclSecurity": (2, [2, 6, 0x20]),
    "MemberRefParent": (3, [2, 1, 0x1A, 6, 0x1B]),
    "HasSemantics": (1, [0x14, 0x17]),
    "MethodDefOrRef": (1, [6, 10]),
    "MemberForwarded": (1, [4, 6]),
    "Implementation": (2, [0x26, 0x23, 0x27]),
    "CustomAttributeType": (3, [None, None, 6, 10, None]),
    "ResolutionScope": (2, [0, 0x1A, 0x23, 1]),
    "TypeOrMethodDef": (1, [2, 6]),
}

# The columns of the tables (II.22): a kind is "u16", "u32", "str", "guid",
# "blob", a table number, or a coded index kind.
SCHEMA = {
    0x00: ["u16", "str", "guid", "guid", "guid"],
    0x01: ["ResolutionScope", "str", "str"],
    0x02: ["u32", "str", "str", "TypeDefOrRef", 4, 6],
    0x03: [4],
    0x04: ["u16", "str", "blob"],
    0x05: [6],
    0x06: ["u32", "u16", "u16", "str", "blob", 8],
    0x07: [8],
    0x08: ["u16", "u16", "str"],
    0x09: [2, "TypeDefOrRef"],
    0x0A: ["MemberRefParent", "str", "blob"],
    0x0B: ["u16", "HasConstant", "blob"],
    0x0C: ["HasCustomAttribute", "CustomAttributeType", "blob"],
    0x0D: ["HasFieldMarshal", "blob"],
    0x0E: ["u16", "HasDeclSecurity", "blob"],
    0x0F: ["u16", "u32", 2],
    0x10: ["u32", 4],
    0x11: ["blob"],
    0x12: [2, 0x14],
    0x13: [0x14],
    0x14: ["u16", "str", "TypeDefOrRef"],
    0x15: [2, 0x17],
    0x16: [0x17],
    0x17: ["u16", "str", "blob"],
    0x18: ["u16", 6, "HasSemantics"],
    0x19: [2, "MethodDefOrRef", "MethodDefOrRef"],
    0x1A: ["str"],
    0x1B: ["blob"],
    0x1C: ["u16", "MemberForwarded", "str", 0x1A],
    0x1D: ["u32", 4],
    0x1E: ["u32", "u32"],
    0x1F: ["u32"],
    0x20: ["u32", "u16", "u16", "u16", "u16", "u32", "blob", "str", "str"],
    0x21: ["u32"],
    0x22: ["u32", "u32", "u32"],
    0x23: ["u16", "u16", "u16", "u16", "u32", "blob", "str", "str", "blob"],
    0x24: ["u32", 0x23],
    0x25: ["u32", "u32", "u32", 0x23],
    0x26: ["u32", "str", "blob"],
    0x27: ["u32", "u32", "str", "str", "Implementation"],
    0x28: ["u32", "u32", "str", "Implementation"],
    0x29: [2, 2],
    0x2A: ["u16", "u16", "TypeOrMethodDef", "str"],
    0x2B: ["MethodDefOrRef", "blob"],
    0x2C: [0x2A, "TypeDefOrRef"],
}

MODULE, TYPE_DEF, METHOD_DEF, CONSTANT, DECL_SECURITY, ENC_LOG = 0, 2, 6, 0x0B, 0x0E, 0x1E


def align(value, to=4):
    return (value + to - 1) // to * to


class Tables:
    """The rows of a #~ stream (II.24.2.6), read with the widths of its header."""

    def __init__(self, data):
        self.prefix = data[:8]
        self.heap_sizes = data[6]
        self.valid, self.sorted = struct.unpack_from("<QQ", data, 8)
        counts = [0] * 64
        pos = 24
        for bit in range(64):
            if self.valid >> bit & 1:
                counts[bit] = struct.unpack_from("<I", data, pos)[0]
                pos += 4
        if self.heap_sizes & 0x40:
            pos += 4
        self.rows = {}
        widths = self.widths(self.heap_sizes, counts)
        for table in sorted(SCHEMA):
            self.rows[table] = []
            for _ in range(counts[table]):
                row = []
                for width in widths[table]:
                    row.append(int.from_bytes(data[pos:pos + width], "little"))
                    pos += width
                self.rows[table].append(row)

    @staticmethod
    def widths(heap_sizes, counts):
        def width(kind):
            if kind in ("u16", "u32"):
                return 2 if kind == "u16" else 4
            if kind in ("str", "guid", "blob"):
                return 4 if heap_sizes & {"str": 1, "guid": 2, "blob": 4}[kind] else 2
            if isinstance(kind, int):
                return 4 if counts[kind] > 0xFFFF else 2
            bits, tables = CODED[kind]
            return 4 if max(counts[t] for t in tables if t is not None) >= 1 << (16 - bits) else 2
        return {table: [width(kind) for kind in kinds] for table, kinds in SCHEMA.items()}

    def write(self, heap_sizes=None, extra=None, unknown=(), trailer=b"\0"):
        """Writes the stream. `extra` sets bit 0x40 and its data, and `unknown`
        adds valid bits with row counts of tables without rows."""
        heap_sizes = self.heap_sizes if heap_sizes is None else heap_sizes
        heap_sizes = heap_sizes | 0x40 if extra is not None else heap_sizes & ~0x40
        counts = [0] * 64
        for table, rows in self.rows.items():
            counts[table] = len(rows)
        valid = sum(1 << t for t, rows in self.rows.items() if rows)
        for bit, count in unknown:
            counts[bit] = count
            valid |= 1 << bit
        out = bytearray(self.prefix[:6]) + bytes([heap_sizes, self.prefix[7]])
        out += struct.pack("<QQ", valid, self.sorted)
        for bit in range(64):
            if valid >> bit & 1:
                out += struct.pack("<I", counts[bit])
        if extra is not None:
            out += struct.pack("<I", extra)
        widths = self.widths(heap_sizes, [len(self.rows.get(t, [])) for t in range(64)])
        for table in sorted(SCHEMA):
            for row in self.rows[table]:
                for value, width in zip(row, widths[table]):
                    out += value.to_bytes(width, "little")
        out += trailer
        return bytes(out) + b"\0" * (align(len(out)) - len(out))


class Metadata:
    """The metadata root (II.24.2.1) and its streams as [name, bytes] pairs."""

    def __init__(self, data):
        assert data[:4] == b"BSJB"
        self.head = data[4:12]
        length = struct.unpack_from("<I", data, 12)[0]
        self.version = data[16:16 + length]
        pos = 16 + length
        self.flags, count = struct.unpack_from("<HH", data, pos)
        pos += 4
        self.streams = []
        for _ in range(count):
            offset, size = struct.unpack_from("<II", data, pos)
            end = data.index(b"\0", pos + 8)
            name = data[pos + 8:end]
            pos += 8 + align(len(name) + 1)
            self.streams.append([name, data[offset:offset + size]])

    def stream(self, name):
        return next(s for s in self.streams if s[0] == name)

    def write(self, sizes=None):
        """Writes the root. `sizes` makes the header of a stream, by position,
        claim another size."""
        out = b"BSJB" + self.head + struct.pack("<I", len(self.version)) + self.version
        out += struct.pack("<HH", self.flags, len(self.streams))
        offset = align(len(out) + sum(8 + align(len(n) + 1) for n, _ in self.streams))
        body = b""
        for index, (name, data) in enumerate(self.streams):
            size = (sizes or {}).get(index, len(data))
            out += struct.pack("<II", offset + len(body), size)
            out += name + b"\0" * (align(len(name) + 1) - len(name))
            body += data + b"\0" * (align(len(data)) - len(data))
        return out + b"\0" * (offset - len(out)) + body


class Pe:
    """A PE image whose .text section grows at its end."""

    def __init__(self, path):
        self.data = bytearray(open(path, "rb").read())
        pe = struct.unpack_from("<I", self.data, 0x3C)[0]
        self.count = struct.unpack_from("<H", self.data, pe + 6)[0]
        optional = pe + 24
        self.table = optional + struct.unpack_from("<H", self.data, pe + 20)[0]
        self.file_align = struct.unpack_from("<I", self.data, optional + 36)[0]
        magic = struct.unpack_from("<H", self.data, optional)[0]
        directories = optional + (96 if magic == 0x10B else 112)
        self.cli = self.offset(struct.unpack_from("<I", self.data, directories + 14 * 8)[0])

    def sections(self):
        for index in range(self.count):
            at = self.table + 40 * index
            yield (at,) + struct.unpack_from("<8sIIII", self.data, at)

    def offset(self, rva):
        for _, _, vsize, va, rsize, roff in self.sections():
            if va <= rva < va + max(vsize, rsize):
                return roff + rva - va
        raise ValueError(hex(rva))

    def read(self, rva, size):
        return bytes(self.data[self.offset(rva):self.offset(rva) + size])

    def metadata(self):
        rva, size = struct.unpack_from("<II", self.data, self.cli + 8)
        return Metadata(self.read(rva, size))

    def append(self, blob):
        """Appends bytes at a multiple of 4 after the end of .text."""
        at, name, vsize, va, rsize, roff = next(self.sections())
        assert name.startswith(b".text")
        start = align(vsize)
        new_vsize = start + len(blob)
        assert va + new_vsize <= min(s[3] for s in self.sections() if s[3] > va)
        new_rsize = align(new_vsize, self.file_align)
        grow = new_rsize - rsize
        if grow:
            self.data[roff + rsize:roff + rsize] = b"\0" * grow
            for s_at, _, _, s_va, _, s_roff in list(self.sections()):
                if s_va != va and s_roff >= roff + rsize:
                    struct.pack_into("<I", self.data, s_at + 20, s_roff + grow)
            struct.pack_into("<I", self.data, at + 16, new_rsize)
        struct.pack_into("<I", self.data, at + 8, new_vsize)
        self.data[roff + start:roff + start + len(blob)] = blob
        return va + start

    def set_metadata(self, blob):
        struct.pack_into("<II", self.data, self.cli + 8, self.append(blob), len(blob))


def string_index(md, text):
    return md.stream(b"#Strings")[1].index(text + b"\0")


def method_row(md, tables, name):
    index = string_index(md, name)
    return next(i for i, row in enumerate(tables.rows[METHOD_DEF]) if row[3] == index)


def renamed_heaps(md):
    """Copies of the heaps with a visible change in each: Circle becomes
    Cercle, "checksum " becomes "CHECKSUM ", the first GUID byte flips, and
    the constant Green becomes 9."""
    strings = md.stream(b"#Strings")[1].replace(b"Circle\0", b"Cercle\0")
    us = md.stream(b"#US")[1].replace("checksum".encode("utf-16-le"),
                                       "CHECKSUM".encode("utf-16-le"))
    guid = bytearray(md.stream(b"#GUID")[1])
    guid[0] ^= 0xFF
    tables = Tables(md.stream(b"#~")[1])
    green = tables.rows[CONSTANT][1][2]
    blob = bytearray(md.stream(b"#Blob")[1])
    assert blob[green:green + 2] == b"\x04\x02"
    blob[green + 1] = 9
    return [[b"#Strings", strings], [b"#US", us], [b"#GUID", bytes(guid)], [b"#Blob", bytes(blob)]]


def heaps_after(pe, md):
    md.streams += renamed_heaps(md)


def heaps_schema(pe, md):
    md.streams += renamed_heaps(md) + [[b"#Schema", b"\0" * 4]]


def heaps_dash_case(pe, md):
    fake = renamed_heaps(md)[0][1]
    md.stream(b"#~")[0] = b"#-"
    md.streams.insert(1, [b"#STRINGS", fake])


def stream_names(pe, md):
    md.streams += [[b"\xFF\xFE\x80junk", b"\x01\x02\x03\x04"], [b"#strings", b"\0" * 4],
                   [b"#JTD", b""], [b"N" * 31, b"\0" * 4]]


def header_quirks(pe, md):
    md.version = b"v4.0.30319\0\0\0"
    stream = md.stream(b"#~")
    stream[1] = Tables(stream[1]).write(heap_sizes=0x07 | 0x20 | 0x80, extra=0x1A2B3C4D,
                                        unknown=[(0x2D, 5), (0x30, 3), (0x3F, 1)])


def version_non_utf8(pe, md):
    md.version = b"v4.0.30319\xFF\xFE\0\0"


def names(pe, md):
    strings = md.stream(b"#Strings")
    strings[1] = strings[1].replace(b"Circle\0", b"C\xFFrcle\0")
    blob = md.stream(b"#Blob")
    assert blob[1][0] == 0
    blob[1] = b"\x02" + blob[1][1:]
    guids = next(i for i, s in enumerate(md.streams) if s[0] == b"#GUID")
    return md.write(sizes={guids: 8})


def rows(pe, md):
    stream = md.stream(b"#~")
    tables = Tables(stream[1])
    tables.rows[MODULE].append([0, 0x7FFF, 0, 0, 0])
    tables.rows[DECL_SECURITY].append([2, 0x7FFF, 0x7FFF])
    tables.rows[ENC_LOG] += [[0x12345678, 0x9ABCDEF0], [0xFFFFFFFF, 7]]
    stream[1] = tables.write()


def divide_parts(pe, md):
    tables = Tables(md.stream(b"#~")[1])
    row = method_row(md, tables, b"Divide")
    rva = tables.rows[METHOD_DEF][row][0]
    head = pe.read(rva, 12)
    flags, max_stack, code_size, local = struct.unpack("<HHII", head)
    code = pe.read(rva + 12, code_size)
    sect = pe.read(rva + align(12 + code_size), 4)
    clauses = pe.read(rva + align(12 + code_size) + 4, sect[1] - 4)
    return tables, row, flags & 0xFFF, max_stack, code, local, clauses


def set_divide(pe, md, tables, row, body):
    tables.rows[METHOD_DEF][row][0] = pe.append(body)
    md.stream(b"#~")[1] = tables.write()


def fat_header(flags, max_stack, code, local, dwords=3):
    head = struct.pack("<HHII", flags | dwords << 12, max_stack, len(code), local)
    head += b"\0" * (4 * dwords - 12) + code
    return head + b"\0" * (align(len(head)) - len(head))


def bodies(pe, md):
    """Divide: a header of 4 dwords with the flags 0x900, a section whose
    DataSize leaves out its header, a catch with the unknown flag 0x8, and an
    unknown section after the clauses."""
    tables, row, flags, max_stack, code, local, clauses = divide_parts(pe, md)
    clauses = bytearray(clauses)
    struct.pack_into("<H", clauses, 0, 0x8)
    body = fat_header(flags | 0x900, max_stack, code, local, dwords=4)
    body += bytes([0x81, len(clauses), 0, 0]) + clauses + bytes([0x02, 8, 0, 0, 1, 2, 3, 4])
    set_divide(pe, md, tables, row, body)


def bodies_hidden_eh(pe, md):
    """Divide: an unknown first section hides the clauses from the runtime, so
    the DivideByZeroException escapes."""
    tables, row, flags, max_stack, code, local, clauses = divide_parts(pe, md)
    body = fat_header(flags, max_stack, code, local)
    body += bytes([0x82, 4, 0, 0, 0x01, 4 + len(clauses), 0, 0]) + clauses
    set_divide(pe, md, tables, row, body)


SAMPLE = ["checksum 17", "type Circle", "constant 2", "key 0"]
RENAMED = ["CHECKSUM 17", "type Cercle", "constant 9", "key 0"]
ESCAPES = ["DivideByZeroException"]

# Each patched fixture: its name, the patch, and the output lines that each
# runtime must print (None: the runtime rejects the fixture).
VARIANTS = [
    ("heaps-after", heaps_after, RENAMED, RENAMED),
    ("heaps-schema", heaps_schema, SAMPLE, SAMPLE),
    ("heaps-dash-case", heaps_dash_case, ["checksum 17", "type Cercle"], ["checksum 17", "type Cercle"]),
    ("stream-names", stream_names, SAMPLE, SAMPLE),
    ("header-quirks", header_quirks, SAMPLE, SAMPLE),
    ("version-non-utf8", version_non_utf8, SAMPLE, None),
    # Reflection gives "C\ufffdrcle"; the console code page prints it as "C?rcle".
    ("names", names, ["checksum 17", "type C?rcle", "constant 2", "key 0"],
     ["checksum 17", "type C?rcle", "constant 2", "key 0"]),
    ("rows", rows, SAMPLE, SAMPLE),
    ("bodies", bodies, SAMPLE, SAMPLE),
    ("bodies-hidden-eh", bodies_hidden_eh, ESCAPES, ESCAPES),
]

CONFUSER = [
    ("confuserex-invalid-metadata", '<protection id="invalid metadata" />', SAMPLE, SAMPLE),
    ("confuserex-anti-tamper",
     '<protection id="anti tamper" /><protection id="invalid metadata" />', SAMPLE, SAMPLE),
    ("confuserex-maximum", None, None, SAMPLE),
]


def run(path):
    """Runs a fixture on CoreCLR and on .NET Framework, and returns the text
    of each run. Each fixture runs alone in a directory: every fixture is the
    assembly `sample`, and the CoreCLR host would bind that name to another
    fixture of the same directory."""
    directory = os.path.join(CACHE, "run", os.path.splitext(os.path.basename(path))[0])
    shutil.rmtree(directory, ignore_errors=True)
    os.makedirs(directory)
    copy = os.path.join(directory, os.path.basename(path))
    shutil.copy(path, copy)
    config = os.path.join(directory, "fixture.runtimeconfig.json")
    with open(config, "w") as file:
        file.write(RUNTIME_CONFIG)
    results = []
    for command in (["dotnet", "exec", "--runtimeconfig", config, copy], [copy]):
        try:
            done = subprocess.run(command, capture_output=True, timeout=30, cwd=directory,
                                  env=dict(os.environ, DOTNET_DbgEnableMiniDump="0"))
            text = (done.stdout + done.stderr).decode("utf-8", "replace")
            results.append(f"exit {done.returncode}\n{text}")
        except subprocess.TimeoutExpired:
            results.append("timeout")
    return results


def check(name, path, core, fx, log):
    failures = []
    for runtime, text, expected in zip(("CoreCLR", ".NET Framework"), run(path), (core, fx)):
        log.write(f"== {name} on {runtime}\n{text.strip()}\n")
        loaded = text.startswith("exit 0") or "DivideByZeroException" in text
        if expected is None:
            continue
        missing = [line for line in expected if line not in text]
        if not loaded or missing:
            failures.append(f"{name} on {runtime}: missing {missing}")
    return failures


def confuser():
    tool = os.path.join(CACHE, "confuserex", "Confuser.CLI.exe")
    if not os.path.exists(tool):
        archive = os.path.join(CACHE, "ConfuserEx-CLI.zip")
        urllib.request.urlretrieve(CONFUSER_URL, archive)
        zipfile.ZipFile(archive).extractall(os.path.join(CACHE, "confuserex"))
    return tool


def main():
    os.makedirs(CACHE, exist_ok=True)
    sample = os.path.join(HERE, "sample.exe")
    subprocess.run([CSC, "/nologo", "/optimize+", f"/out:{sample}",
                    os.path.join(HERE, "Sample.cs")], check=True)
    for name, rule, _, _ in CONFUSER:
        out = os.path.join(CACHE, name)
        rule = (f'<rule pattern="true" inherit="false">{rule}</rule>' if rule
                else '<rule pattern="true" preset="maximum" inherit="false" />')
        project = os.path.join(CACHE, name + ".crproj")
        with open(project, "w") as file:
            file.write(f'<project outputDir="{out}" baseDir="{HERE}" seed="clrmeta-{name}" '
                       f'xmlns="http://confuser.codeplex.com">{rule}'
                       f'<module path="sample.exe" /></project>')
        subprocess.run([confuser(), "-n", project], check=True, capture_output=True)
        shutil.copy(os.path.join(out, "sample.exe"), os.path.join(HERE, name + ".exe"))
    for name, patch, _, _ in VARIANTS:
        pe = Pe(sample)
        md = pe.metadata()
        blob = patch(pe, md) or md.write()
        pe.set_metadata(blob)
        with open(os.path.join(HERE, name + ".exe"), "wb") as file:
            file.write(pe.data)
    failures = []
    with open(os.path.join(HERE, "runs.txt"), "w", encoding="utf-8") as log:
        for name, core, fx in [("sample", SAMPLE, SAMPLE)] + \
                [(n, c, f) for n, _, c, f in CONFUSER] + [(n, c, f) for n, _, c, f in VARIANTS]:
            failures += check(name, os.path.join(HERE, name + ".exe"), core, fx, log)
    if failures:
        sys.exit("\n".join(failures))
    print("every fixture runs as it expects; see runs.txt")


if __name__ == "__main__":
    main()
