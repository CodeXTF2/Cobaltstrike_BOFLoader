
"""
BOF Packer - Generates blob for BOFLoader from a COFF .o file

Usage: python bof_pack.py <bof.o> [--args "arg1 arg2 ..."] [--format "Ziz"] [--entry go]

Format characters (bof_pack style):
  b - raw bytes (pass as hex string, e.g. "deadbeef")
  i - 32-bit integer
  s - 16-bit short
  z - null-terminated ASCII string
  Z - null-terminated wide (UTF-16LE) string
"""

import struct
import argparse
import sys
from pathlib import Path


# Section target codes for relocations
SYM_RDATA = 1024      # sec2 (.rdata)
SYM_DATA = 1025       # sec3 (.data)
SYM_TEXT = 1026       # .text
SYM_DYNAMIC = 1027    # dynamic Win32 API (LoadLibrary/GetProcAddress)
SYM_END = 1028        # end marker
SYM_SEC4 = 1029       # sec4
SYM_SEC5 = 1030       # sec5
SYM_BSS = 1031        # .bss

# Base section codes (which section the reloc is IN)
BASE_TEXT = 1026
BASE_DATA = 1025
BASE_SEC5 = 1030


class COFFParser:
    """Parse a COFF object file (.o)"""

    # COFF header format
    HEADER_SIZE = 20
    SECTION_HEADER_SIZE = 40
    SYMBOL_SIZE = 18
    RELOC_SIZE = 10

    # Machine types
    IMAGE_FILE_MACHINE_I386 = 0x014c
    IMAGE_FILE_MACHINE_AMD64 = 0x8664

    def __init__(self, data: bytes):
        self.data = data
        self.sections = {}
        self.symbols = []
        self.string_table = b''
        self.machine = 0
        self.is_64bit = False

    def parse(self):
        """Parse the COFF file"""
        # Parse file header
        (self.machine, num_sections, timestamp, symtab_offset,
         num_symbols, opt_header_size, characteristics) = struct.unpack_from(
            '<HHIIIHH', self.data, 0)

        self.is_64bit = self.machine == self.IMAGE_FILE_MACHINE_AMD64

        # Parse string table (comes after symbol table)
        if symtab_offset > 0 and num_symbols > 0:
            strtab_offset = symtab_offset + num_symbols * self.SYMBOL_SIZE
            if strtab_offset < len(self.data):
                strtab_size = struct.unpack_from('<I', self.data, strtab_offset)[0]
                self.string_table = self.data[strtab_offset:strtab_offset + strtab_size]

        # Parse symbol table
        if symtab_offset > 0:
            self._parse_symbols(symtab_offset, num_symbols)

        # Parse section headers
        offset = self.HEADER_SIZE + opt_header_size
        for i in range(num_sections):
            self._parse_section(offset, i + 1)
            offset += self.SECTION_HEADER_SIZE

    def _get_string(self, offset_or_name: bytes) -> str:
        """Get a string from the string table or inline name"""
        if offset_or_name[:4] == b'\x00\x00\x00\x00':
            # Offset into string table
            str_offset = struct.unpack('<I', offset_or_name[4:8])[0]
            if str_offset < len(self.string_table):
                end = self.string_table.find(b'\x00', str_offset)
                if end == -1:
                    end = len(self.string_table)
                return self.string_table[str_offset:end].decode('ascii', errors='replace')
            return ''
        else:
            # Inline name (up to 8 chars, null-padded)
            return offset_or_name.rstrip(b'\x00').decode('ascii', errors='replace')

    def _parse_symbols(self, offset: int, count: int):
        """Parse the symbol table"""
        i = 0
        while i < count:
            sym_offset = offset + i * self.SYMBOL_SIZE
            name_bytes = self.data[sym_offset:sym_offset + 8]
            value, section_num, sym_type, storage_class, num_aux = struct.unpack_from(
                '<IHHBB', self.data, sym_offset + 8)

            name = self._get_string(name_bytes)
            self.symbols.append({
                'name': name,
                'value': value,
                'section': section_num,
                'type': sym_type,
                'storage_class': storage_class,
                'aux_count': num_aux
            })

            # Skip auxiliary symbol entries
            i += 1 + num_aux
            for _ in range(num_aux):
                self.symbols.append(None)  # Placeholder for aux symbols

    def _parse_section(self, offset: int, section_num: int):
        """Parse a section header"""
        name_bytes = self.data[offset:offset + 8]
        name = self._get_string(name_bytes)

        (virtual_size, virtual_addr, raw_size, raw_offset,
         reloc_offset, linenum_offset, num_relocs, num_linenums,
         characteristics) = struct.unpack_from('<IIIIIIHHI', self.data, offset + 8)

        # Read section data
        section_data = b''
        if raw_size > 0 and raw_offset > 0:
            section_data = self.data[raw_offset:raw_offset + raw_size]

        # Parse relocations for this section
        relocs = []
        if num_relocs > 0 and reloc_offset > 0:
            for i in range(num_relocs):
                r_offset = reloc_offset + i * self.RELOC_SIZE
                r_vaddr, r_symidx, r_type = struct.unpack_from('<IIH', self.data, r_offset)
                relocs.append({
                    'offset': r_vaddr,
                    'symbol_index': r_symidx,
                    'type': r_type
                })

        self.sections[name] = {
            'number': section_num,
            'data': section_data,
            'size': raw_size,
            'virtual_size': virtual_size,
            'relocations': relocs,
            'characteristics': characteristics
        }

    def get_symbol_name(self, index: int) -> str:
        """Get symbol name by index"""
        if 0 <= index < len(self.symbols) and self.symbols[index]:
            return self.symbols[index]['name']
        return ''

    def get_symbol_section(self, index: int) -> int:
        """Get section number for a symbol"""
        if 0 <= index < len(self.symbols) and self.symbols[index]:
            return self.symbols[index]['section']
        return 0

    def get_symbol_value(self, index: int) -> int:
        """Get symbol value (offset within section)"""
        if 0 <= index < len(self.symbols) and self.symbols[index]:
            return self.symbols[index]['value']
        return 0

    def find_entry_point(self, func_name: str = 'go') -> int:
        """Find the entry point offset for the given function"""
        for sym in self.symbols:
            if sym is None:
                continue
            name = sym['name']
            # Check for both with and without underscore prefix
            if name == func_name or name == '_' + func_name:
                if sym['section'] > 0:  # Must be defined in a section
                    return sym['value']
        return 0


# Beacon API symbol name -> function table slot index
# Must match the slot order in bofloader.c's init_dummy_beacon_table()
BEACON_API_SLOTS = {
    'BeaconDataParse':                0,
    'BeaconDataInt':                  1,
    'BeaconDataShort':                2,
    'BeaconDataLength':               3,
    'BeaconDataExtract':              4,
    'BeaconFormatAlloc':              5,
    'BeaconFormatReset':              6,
    'BeaconFormatFree':               7,
    'BeaconFormatAppend':             8,
    'BeaconFormatPrintf':             9,
    'BeaconFormatToString':          10,
    'BeaconFormatInt':               11,
    'BeaconPrintf':                  12,
    'BeaconOutput':                  13,
    'BeaconUseToken':                14,
    'BeaconRevertToken':             15,
    'BeaconIsAdmin':                 16,
    'BeaconGetSpawnTo':              17,
    'BeaconInjectProcess':           18,
    'BeaconInjectTemporaryProcess':  19,
    'BeaconCleanupProcess':          20,
    'toWideChar':                    21,
}


def get_beacon_api_slot(name: str) -> int:
    """If name is a Beacon API import (__imp_BeaconXxx), return its slot index, else -1"""
    for prefix in ('__imp_', '__imp__'):
        if name.startswith(prefix):
            api_name = name[len(prefix):]
            if api_name in BEACON_API_SLOTS:
                return BEACON_API_SLOTS[api_name]
    return -1


def is_dynamic_function(name: str) -> bool:
    """Check if symbol is a dynamic Win32 API (Module$Function pattern)"""
    if not (name.startswith('__imp__') or name.startswith('__imp_')):
        return False
    # Remove prefix and check for Module$Function pattern
    stripped = name[7:] if name.startswith('__imp__') else name[6:]
    parts = stripped.split('$')
    return len(parts) == 2 and len(parts[0]) > 0 and len(parts[1]) > 0


def parse_dynamic_function(name: str) -> tuple:
    """Parse Module$Function into (module, function)"""
    stripped = name[7:] if name.startswith('__imp__') else name[6:]
    parts = stripped.split('$')
    func = parts[1].split('@')[0]  # Remove @ordinal suffix if present
    return (parts[0], func)


def get_section_target(section_name: str) -> int:
    """Get the target code for a section name"""
    mapping = {
        '.rdata': SYM_RDATA,
        '.data': SYM_DATA,
        '.text': SYM_TEXT,
        '.bss': SYM_BSS,
    }
    return mapping.get(section_name, 0)


def get_section_base(section_name: str) -> int:
    """Get the base code for relocations within a section"""
    mapping = {
        '.text': BASE_TEXT,
        '.data': BASE_DATA,
    }
    return mapping.get(section_name, BASE_TEXT)


class BlobBuilder:
    """Build the BOF blob for the loader"""

    def __init__(self, coff: COFFParser):
        self.coff = coff
        self.relocs = bytearray()

    def pack_args(self, format_str: str, args: list) -> bytes:
        """Pack arguments using bof_pack format"""
        result = bytearray()
        arg_idx = 0

        for char in format_str:
            if char == ' ':
                continue
            if arg_idx >= len(args):
                raise ValueError(f"Not enough arguments for format '{format_str}'")

            arg = args[arg_idx]
            arg_idx += 1

            if char == 'b':
                # Raw bytes (hex string)
                if isinstance(arg, str):
                    data = bytes.fromhex(arg)
                else:
                    data = arg
                result.extend(struct.pack('<I', len(data)))
                result.extend(data)

            elif char == 'i':
                # 32-bit integer
                result.extend(struct.pack('<I', int(arg)))

            elif char == 's':
                # 16-bit short
                result.extend(struct.pack('<H', int(arg)))

            elif char == 'z':
                # Null-terminated ASCII string
                if isinstance(arg, str):
                    data = arg.encode('ascii') + b'\x00'
                else:
                    data = arg + b'\x00'
                result.extend(struct.pack('<I', len(data)))
                result.extend(data)

            elif char == 'Z':
                # Null-terminated wide string (UTF-16LE)
                if isinstance(arg, str):
                    data = arg.encode('utf-16-le') + b'\x00\x00'
                else:
                    data = arg.encode('utf-16-le') + b'\x00\x00'
                result.extend(struct.pack('<I', len(data)))
                result.extend(data)

            else:
                raise ValueError(f"Unknown format character: '{char}'")

        return bytes(result)

    def add_reloc(self, base: int, reloc_type: int, sym: int, offset: int, addend: int):
        """Add a 16-byte relocation record"""
        self.relocs.extend(struct.pack('<I', base))      # base section (LE u32)
        self.relocs.extend(struct.pack('<H', reloc_type)) # type (LE u16)
        self.relocs.extend(struct.pack('<H', sym))       # target (LE u16)
        self.relocs.extend(struct.pack('<I', offset))    # offset (LE u32)
        self.relocs.extend(struct.pack('<I', addend))    # addend (LE u32)

    def add_dynamic_reloc(self, base: int, reloc_type: int, offset: int, module: str, function: str):
        """Add a dynamic function relocation (with module$function strings)"""
        self.add_reloc(base, reloc_type, SYM_DYNAMIC, offset, 0)
        # Module and function names are BE length-prefixed, null-terminated
        mod_bytes = module.encode('ascii') + b'\x00'
        func_bytes = function.encode('ascii') + b'\x00'
        self.relocs.extend(struct.pack('>I', len(mod_bytes)))
        self.relocs.extend(mod_bytes)
        self.relocs.extend(struct.pack('>I', len(func_bytes)))
        self.relocs.extend(func_bytes)

    def add_end_marker(self):
        """Add the relocation end marker"""
        self.add_reloc(BASE_TEXT, 0, SYM_END, 0, 0)

    def process_relocations(self):
        """Process all relocations from the COFF"""
        # Get section number to name mapping
        section_num_to_name = {}
        for name, section in self.coff.sections.items():
            section_num_to_name[section['number']] = name

        # Process .text relocations (most common case)
        if '.text' in self.coff.sections:
            text_section = self.coff.sections['.text']
            for reloc in text_section['relocations']:
                sym_idx = reloc['symbol_index']
                sym_name = self.coff.get_symbol_name(sym_idx)
                sym_section = self.coff.get_symbol_section(sym_idx)
                sym_value = self.coff.get_symbol_value(sym_idx)
                offset = reloc['offset']
                reloc_type = reloc['type']

                # Determine target
                if is_dynamic_function(sym_name):
                    # Dynamic Win32 API
                    module, func = parse_dynamic_function(sym_name)
                    self.add_dynamic_reloc(BASE_TEXT, reloc_type, offset, module, func)
                elif sym_section > 0:
                    # Section-relative symbol
                    target_section_name = section_num_to_name.get(sym_section, '')
                    target_code = get_section_target(target_section_name)
                    if target_code:
                        self.add_reloc(BASE_TEXT, reloc_type, target_code, offset, sym_value)
                    else:
                        print(f"Warning: Unknown target section '{target_section_name}' for symbol '{sym_name}'")
                else:
                    # External symbol - check if it's a Beacon API
                    slot = get_beacon_api_slot(sym_name)
                    if slot >= 0:
                        self.add_reloc(BASE_TEXT, reloc_type, slot, offset, 0)
                    else:
                        print(f"Warning: Unresolved external symbol '{sym_name}' at offset {offset}")

        # Process .data relocations if any
        if '.data' in self.coff.sections:
            data_section = self.coff.sections['.data']
            for reloc in data_section['relocations']:
                sym_idx = reloc['symbol_index']
                sym_name = self.coff.get_symbol_name(sym_idx)
                sym_section = self.coff.get_symbol_section(sym_idx)
                sym_value = self.coff.get_symbol_value(sym_idx)
                offset = reloc['offset']
                reloc_type = reloc['type']

                if is_dynamic_function(sym_name):
                    module, func = parse_dynamic_function(sym_name)
                    self.add_dynamic_reloc(BASE_DATA, reloc_type, offset, module, func)
                elif sym_section > 0:
                    target_section_name = section_num_to_name.get(sym_section, '')
                    target_code = get_section_target(target_section_name)
                    if target_code:
                        self.add_reloc(BASE_DATA, reloc_type, target_code, offset, sym_value)
                else:
                    slot = get_beacon_api_slot(sym_name)
                    if slot >= 0:
                        self.add_reloc(BASE_DATA, reloc_type, slot, offset, 0)

        self.add_end_marker()

    def build(self, entry_func: str = 'go', packed_args: bytes = b'') -> bytes:
        """Build the complete blob"""
        # Get sections
        text_data = self.coff.sections.get('.text', {}).get('data', b'')
        rdata_data = self.coff.sections.get('.rdata', {}).get('data', b'')
        data_data = self.coff.sections.get('.data', {}).get('data', b'')

        # Calculate BSS size
        bss_size = 0
        if '.bss' in self.coff.sections:
            bss_section = self.coff.sections['.bss']
            bss_size = bss_section.get('virtual_size', 0) or bss_section.get('size', 0)

        # sec4 and sec5 are typically empty for standard BOFs
        sec4_data = b''
        sec5_data = b''

        # Process relocations
        self.process_relocations()

        # Find entry point
        entry_offset = self.coff.find_entry_point(entry_func)

        # Build the blob (all lengths are big-endian)
        blob = bytearray()

        # 1. BSS size (BE u32)
        blob.extend(struct.pack('>I', bss_size))

        # 2. .text section (BE u32 len + data)
        blob.extend(struct.pack('>I', len(text_data)))
        blob.extend(text_data)

        # 3. sec2/.rdata (BE u32 len + data)
        blob.extend(struct.pack('>I', len(rdata_data)))
        blob.extend(rdata_data)

        # 4. sec3/.data (BE u32 len + data)
        blob.extend(struct.pack('>I', len(data_data)))
        blob.extend(data_data)

        # 5. sec4 (BE u32 len + data)
        blob.extend(struct.pack('>I', len(sec4_data)))
        blob.extend(sec4_data)

        # 6. sec5 (BE u32 len + data)
        blob.extend(struct.pack('>I', len(sec5_data)))
        blob.extend(sec5_data)

        # 7. Relocations (BE u32 len + data)
        blob.extend(struct.pack('>I', len(self.relocs)))
        blob.extend(self.relocs)

        # 8. Entry offset (BE u32)
        blob.extend(struct.pack('>I', entry_offset))

        # 9. Arguments (BE u32 len + data)
        blob.extend(struct.pack('>I', len(packed_args)))
        blob.extend(packed_args)

        return bytes(blob)


def main():
    parser = argparse.ArgumentParser(
        description='Pack a BOF (.o) file into a blob for BOFLoader',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Format characters for --format:
  b  raw bytes (pass arg as hex string, e.g., "deadbeef")
  i  32-bit integer
  s  16-bit short
  z  null-terminated ASCII string
  Z  null-terminated wide (UTF-16LE) string

Examples:
  python bof_pack.py mybof.o
  python bof_pack.py mybof.o --args "hello 42" --format "zi"
  python bof_pack.py mybof.o --args "C:\\Windows\\System32" --format "Z"
  python bof_pack.py mybof.o --entry main
''')

    parser.add_argument('bof_file', help='Path to BOF object file (.o)')
    parser.add_argument('--args', '-a', default='', help='Space-separated arguments')
    parser.add_argument('--format', '-f', default='', help='bof_pack format string (e.g., "Ziz")')
    parser.add_argument('--entry', '-e', default='go', help='Entry function name (default: go)')
    parser.add_argument('--output', '-o', default='bof.blob', help='Output file (default: bof.blob)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    # Read BOF file
    bof_path = Path(args.bof_file)
    if not bof_path.exists():
        print(f"Error: BOF file not found: {bof_path}")
        sys.exit(1)

    with open(bof_path, 'rb') as f:
        bof_data = f.read()

    # Parse COFF
    coff = COFFParser(bof_data)
    try:
        coff.parse()
    except Exception as e:
        print(f"Error parsing COFF: {e}")
        sys.exit(1)

    if args.verbose:
        print(f"Machine: {'x64' if coff.is_64bit else 'x86'}")
        print(f"Sections: {list(coff.sections.keys())}")
        for name, sect in coff.sections.items():
            print(f"  {name}: {sect['size']} bytes, {len(sect['relocations'])} relocs")

    # Pack arguments
    packed_args = b''
    if args.format:
        arg_list = args.args.split() if args.args else []
        builder = BlobBuilder(coff)
        try:
            packed_args = builder.pack_args(args.format, arg_list)
        except Exception as e:
            print(f"Error packing arguments: {e}")
            sys.exit(1)
        if args.verbose:
            print(f"Packed args: {len(packed_args)} bytes")

    # Build blob
    builder = BlobBuilder(coff)
    blob = builder.build(args.entry, packed_args)

    # Write output
    output_path = Path(args.output)
    with open(output_path, 'wb') as f:
        f.write(blob)

    print(f"Wrote {len(blob)} bytes to {output_path}")

    if args.verbose:
        entry_offset = coff.find_entry_point(args.entry)
        print(f"Entry point '{args.entry}': offset {entry_offset}")
        print(f"Relocations: {len(builder.relocs)} bytes")


if __name__ == '__main__':
    main()
