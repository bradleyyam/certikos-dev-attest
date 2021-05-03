from __future__ import print_function
import sys
import os
# pip install pycryptodome
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import Crypto.Random
# pip install elftools
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

## INITIALIZE GLOBAL VARS
PAGE_SIZE = 4096
h = SHA256.new()
hdev = SHA256.new()
##certiKOS Public key
n = 0xA1D46FBA2318F8DCEF16C280948B1CF27966B9B47225ED2989F8D74B45BD36049C0AAB5AD0FF003553BA843C8E12782FC5873BB89A3DC84B883D25666CD22BF3ACD5B675969F8BEBFBCAC93FDD927C7442B178B10D1DFF9398E52316AAE0AF74E594650BDC3C670241D418684593CDA1A7B9DC4F20D2FDC6F66344074003E211
e = 0x010001
d = 0x589552BB4F2F023ADDDD5586D0C8FD857512D82080436678D07F984A29D892D31F1F7000FC5A39A0F73E27D885E47249A4148C8A5653EF69F91F8F736BA9F84841C2D99CD8C24DE8B72B5C9BE0EDBE23F93D731749FEA9CFB4A48DD2B7F35A2703E74AA2D4DB7DE9CEEA7D763AF0ADA7AC176C4E9A22C4CDA65CEC0C65964401
p = 0xCD083568D2D46C44C40C1FA0101AF2155E59C70B08423112AF0C1202514BBA5210765E29FF13036F56C7495894D80CF8C3BAEE2839BACBB0B86F6A2965F60DB1
q = 0xCA0EEEA5E710E8E9811A6B846399420E3AE4A4C16647E426DDF8BBBCB11CD3F35CE2E4B6BCAD07AE2C0EC2ECBFCC601B207CDD77B5673E16382B1130BF465261
rsaCertikos = RSA.construct((n, e, d, p, q), consistency_check=True)
##generate developer key
rsaDev = RSA.generate(bits=2048, e=65537)

def ROUND_DOWN(num, divisor):
    return num - (num%divisor)

def ROUND_UP(num, divisor):
    return num + (divisor - num%divisor)

def process_file(filename):
    print('Processing file:', filename)
    with open(filename, 'rb') as f:
        compute_bin_hash(f, filename)

def write_to_file(data, name, mode):
    f = open(name, mode)
    f.write(data)
    f.close()

def compute_bin_hash(stream, filename):
    elffile = ELFFile(stream)
    # find bss range
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
                if va >= eva: break

                if bss_base <= va and va + PAGE_SIZE <= bss_base + bss_size:
                    # skip .bss section
                    length = PAGE_SIZE
                    print('.bss skip')
                    continue

                if va % PAGE_SIZE != 0:
                    # va not aligned to a page, copy a partial page
                    length = min(PAGE_SIZE - va % PAGE_SIZE, zva - va) # +length
                    stream.seek(fa)
                    bites = stream.read(length)
                    h.update(bites)
                    print('1 fa: 0x%08x, va: 0x%08x, eva: 0x%08x, zva: 0x%08x, length: 0x%08x' % (
                        fa, va, zva, eva, length
                    ))

                elif va < ROUND_DOWN(zva, PAGE_SIZE):
                    # copy a complete page
                    length = PAGE_SIZE
                    stream.seek(fa)
                    bites = stream.read(length)
                    h.update(bites)
                    print('2 fa: 0x%08x, va: 0x%08x, eva: 0x%08x, zva: 0x%08x, length: 0x%08x' % (
                        fa, va, zva, eva, length
                    ))

                elif va < zva and ph['p_filesz']:
                     # va aligned to a page, copy partial page
                    length = zva - va
                    stream.seek(fa)
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
        print(h.digest())
        print(len(h.hexdigest()))
        write_to_file(h.hexdigest(), str(filename) + ".dir/bin_hash_hexdigest", "w")
        signature = pkcs1_15.new(rsaDev).sign(h)
        print(signature)
        write_to_file(signature, str(filename) + ".dir/bin_signature", "wb")

if __name__ == '__main__':
    if sys.argv[1] == '--test':
        for filename in sys.argv[2:]:
            os.mkdir(str(filename) + ".dir")
            process_file(filename)
    rsaDevPub = rsaDev.publickey()
    rsaDevPub_PEM = rsaDevPub.exportKey(format='PEM', passphrase=None, pkcs=1, protection=None, randfunc=None)
    write_to_file(rsaDevPub_PEM, str(filename) + ".dir/dev.pem", "wb")
    hdev.update(rsaDevPub_PEM)
    signature = pkcs1_15.new(rsaCertikos).sign(hdev)
    write_to_file(signature, str(filename) + ".dir/dev_signature", "wb")
    