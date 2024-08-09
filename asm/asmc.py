from capstone import *


def read_memory_dump(file_path):
    with open(file_path, 'rb') as file:
        binary_data = file.read()

    return binary_data


def generate_pseudo_c(code, address):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    pseudo_c = []

    register_map = {
        "eax": "int", "ebx": "int", "ecx": "int", "edx": "int",
        "esi": "int", "edi": "int", "ebp": "int", "esp": "int",
        "r8": "int", "r9": "int", "r10": "int", "r11": "int",
        "r12": "int", "r13": "int", "r14": "int", "r15": "int"
    }

    for instr in md.disasm(code, address):
        if instr.mnemonic == 'mov':
            if instr.operands[1].type == 1:  # Register
                pseudo_c.append(f"{instr.operands[0].reg} = {instr.operands[1].reg};")
            elif instr.operands[1].type == 2:  # Immediate
                pseudo_c.append(f"{instr.operands[0].reg} = {instr.operands[1].imm};")
        elif instr.mnemonic == 'add':
            pseudo_c.append(f"{instr.operands[0].reg} += {instr.operands[1].imm};")
        elif instr.mnemonic == 'sub':
            pseudo_c.append(f"{instr.operands[0].reg} -= {instr.operands[1].imm};")
        elif instr.mnemonic == 'call':
            pseudo_c.append(f"{instr.operands[0].imm}();")
        elif instr.mnemonic == 'ret':
            pseudo_c.append("return;")
        elif instr.mnemonic == 'jmp':
            pseudo_c.append(f"goto {instr.operands[0].imm};")
        elif instr.mnemonic == 'cmp':
            pseudo_c.append(f"if ({instr.operands[0].reg} == {instr.operands[1].imm}) " + "{")
        elif instr.mnemonic == 'je':
            pseudo_c.append(f"    goto {instr.operands[0].imm};" + "\n}")
        elif instr.mnemonic == 'jne':
            pseudo_c.append(f"    goto {instr.operands[0].imm};" + "\n}")
        elif instr.mnemonic == 'push':
            pseudo_c.append(f"push({instr.operands[0].reg});")
        elif instr.mnemonic == 'pop':
            pseudo_c.append(f"{instr.operands[0].reg} = pop();")
        else:
            pseudo_c.append(f"// {instr.mnemonic} {instr.op_str}")

    return "\n".join(pseudo_c)