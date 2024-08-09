from elftools.elf.elffile import ELFFile
from capstone import *

def disassemble_elf(filename, dasm=False):
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)

        # Iterate over all the sections to find the ".text" section, which contains the code
        for section in elffile.iter_sections():
            if section.name == '.text':
                code = section.data()
                address = section['sh_addr']

                # Detect the architecture of the ELF file
                if elffile['e_machine'] == 'EM_ARM':
                    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
                elif elffile['e_machine'] == 'EM_AARCH64':
                    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
                else:
                    print(f"Unsupported architecture: {elffile['e_machine']}")
                    return

                # Disassemble the code
                for instruction in md.disasm(code, address):
                    print(f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}")
                    if dasm:
                        with open(f"dump/elf_dump.txt", "a") as f:
                            f.write(f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}\n")