from capstone       import Cs, CS_ARCH_X86, CS_MODE_64
from utils.utils    import Print


def disassemble_code(code, address, dump=True):
    # Initialize Capstone disassembler
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    # Disassemble the binary data
    for instr in md.disasm(code, address):
        Print(f"0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
        if dump:
            with open(f"dump/mem_dump.txt", "a") as f:
                f.write(f"0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}\n")
    if dump:
        with open(f"dump/mem_dump.txt", "a") as f:
            f.write(f"-> ----------------------------------------------- <-\n")

