#-------------------------------------------------------------------------------
# elftools example: elf_low_high_api.py
#
# A simple example that shows some usage of the low-level API pyelftools
# provides versus the high-level API while inspecting an ELF file's symbol
# table.
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import print_function
import sys
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import Crypto.Random

# If pyelftools is not installed, the example can also run from the root or
# examples/ dir of the source distribution.
sys.path[0:0] = ['.', '..']

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

PAGE_SIZE = 4096

h = SHA256.new()

n = 0xA1D46FBA2318F8DCEF16C280948B1CF27966B9B47225ED2989F8D74B45BD36049C0AAB5AD0FF003553BA843C8E12782FC5873BB89A3DC84B883D25666CD22BF3ACD5B675969F8BEBFBCAC93FDD927C7442B178B10D1DFF9398E52316AAE0AF74E594650BDC3C670241D418684593CDA1A7B9DC4F20D2FDC6F66344074003E211
e = 0x010001
d = 0x589552BB4F2F023ADDDD5586D0C8FD857512D82080436678D07F984A29D892D31F1F7000FC5A39A0F73E27D885E47249A4148C8A5653EF69F91F8F736BA9F84841C2D99CD8C24DE8B72B5C9BE0EDBE23F93D731749FEA9CFB4A48DD2B7F35A2703E74AA2D4DB7DE9CEEA7D763AF0ADA7AC176C4E9A22C4CDA65CEC0C65964401
p = 0xCD083568D2D46C44C40C1FA0101AF2155E59C70B08423112AF0C1202514BBA5210765E29FF13036F56C7495894D80CF8C3BAEE2839BACBB0B86F6A2965F60DB1
q = 0xCA0EEEA5E710E8E9811A6B846399420E3AE4A4C16647E426DDF8BBBCB11CD3F35CE2E4B6BCAD07AE2C0EC2ECBFCC601B207CDD77B5673E16382B1130BF465261

rsaCertikos = RSA.construct((n, e), consistency_check=True)
rsaDevice = RSA.generate(bits=2048, e=65537)

def ROUND_DOWN(num, divisor):
    return num - (num%divisor)

def ROUND_UP(num, divisor):
    return num + (divisor - num%divisor)

def process_file(filename):
    print('Processing file:', filename)
    with open(filename, 'rb') as f:
        section_info_lowlevel(f)
        f.seek(0)
        section_info_highlevel(f)


def section_info_lowlevel(stream):
    print('Low level API...')
    # We'll still be using the ELFFile context object. It's just too
    # convenient to give up, even in the low-level API demonstation :-)
    elffile = ELFFile(stream)

    # The e_shnum ELF header field says how many sections there are in a file
    print('  %s sections' % elffile['e_phnum'])

    for i in range(elffile['e_shnum']):
        section_offset = elffile['e_shoff'] + i * elffile['e_shentsize']
        stream.seek(section_offset)
        sh = elffile.structs.Elf_Shdr.parse_stream(stream)
        if sh['sh_type'] == "SHT_NOBITS":
            print('  name: %s, sh type: %s, offset: 0x%08x, size: 0x%08x' % (
                sh['sh_name'], sh['sh_type'], sh['sh_offset'], sh['sh_size']))
            bss_base = sh['sh_addr']
            bss_size = sh['sh_size']

    # Try to find the symbol table
    for i in range(elffile['e_phnum']):
        prog_offset = elffile['e_phoff'] + i * elffile['e_phentsize']
        # Parse the prog header using structs.Elf_Phdr
        stream.seek(prog_offset)
        ph = elffile.structs.Elf_Phdr.parse_stream(stream)
        if ph['p_type'] == 'PT_LOAD':
            fa = ph['p_offset']
            va = ph['p_vaddr']

            zva = ph['p_vaddr'] + ph['p_filesz']
            eva = ROUND_UP(ph['p_vaddr'] + ph['p_memsz'], PAGE_SIZE)

            length = 0

            while va < eva:
                va += length
                fa += length

                if bss_base <= va and va + PAGE_SIZE <= bss_base + bss_size:
                    # skip .bss section
                    length = PAGE_SIZE
                    print('.bss skip')
                    continue

                if va % PAGE_SIZE != 0:
                    # va not aligned to a page, copy a partial page
                    length = min(PAGE_SIZE - va % PAGE_SIZE, zva - va) # +length
                    bites = stream.read(length)
                    h.update(bites)
                    print('1 fa: 0x%08x, va: 0x%08x, eva: 0x%08x, zva: 0x%08x, length: 0x%08x' % (
                        fa, va, zva, eva, length
                    ))

                elif va < ROUND_DOWN(zva, PAGE_SIZE):
                    # copy a complete page
                    length = PAGE_SIZE
                    bites = stream.read(length)
                    h.update(bites)
                    print('2 fa: 0x%08x, va: 0x%08x, eva: 0x%08x, zva: 0x%08x, length: 0x%08x' % (
                        fa, va, zva, eva, length
                    ))

                elif va < zva and ph['p_filesz']:
                     # va aligned to a page, copy partial page
                    length = zva - va
                    bites = stream.read(length)
                    h.update(bites)
                    print('3 fa: 0x%08x, va: 0x%08x, eva: 0x%08x, zva: 0x%08x, length: 0x%08x' % (
                        fa, va, zva, eva, length
                    ))
                    length = PAGE_SIZE

                else:
                    # no file size, zero a page
                    length = PAGE_SIZE
                    print('4 fa: 0x%08x, va: 0x%08x, eva: 0x%08x, zva: 0x%08x, length: 0x%08x' % (
                        fa, va, zva, eva, length
                    ))

            print('  Prog type: %s, offset: 0x%08x, vaddr: 0x%08x, filesz: 0x%08x, memsz: 0x%08x' % (
                    ph['p_type'], ph['p_offset'], ph['p_vaddr'], ph['p_filesz'], ph['p_memsz']))
        else:
            print('  No symbol table found. Perhaps this ELF has been stripped?')
        
        print(h.hexdigest())
        print(len(h.hexdigest()))


def section_info_highlevel(stream):
    print('High level API...')
    elffile = ELFFile(stream)

    # Just use the public methods of ELFFile to get what we need
    # Note that section names are strings.
    print('  %s sections' % elffile.num_sections())
    section = elffile.get_section_by_name('.symtab')

    if not section:
        print('  No symbol table found. Perhaps this ELF has been stripped?')
        return

    # A section type is in its header, but the name was decoded and placed in
    # a public attribute.
    print('  Section name: %s, type: %s' %(
        section.name, section['sh_type']))

    # But there's more... If this section is a symbol table section (which is
    # the case in the sample ELF file that comes with the examples), we can
    # get some more information about it.
    if isinstance(section, SymbolTableSection):
        num_symbols = section.num_symbols()
        print("  It's a symbol section with %s symbols" % num_symbols)
        print("  The name of the last symbol in the section is: %s" % (
            section.get_symbol(num_symbols - 1).name))


if __name__ == '__main__':
    print(rsaDevice.n)
    if sys.argv[1] == '--test':
        for filename in sys.argv[2:]:
            process_file(filename)