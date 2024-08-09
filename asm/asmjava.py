from capstone import *


# Function to load the binary file
def load_binary_file(filename):
    with open(filename, "rb") as f:
        return f.read()


# Function to disassemble the loaded binary code
def disassemble_code(code, start_address=0x1000):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    instructions = []
    for instruction in md.disasm(code, start_address):
        instructions.append(f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}")
    return instructions


# Function to translate assembly code into pseudo-Java code
def translate_to_java(asm_instructions):
    translation = []
    for line in asm_instructions:
        address, instr = line.split(":", 1)
        mnemonic, operands = instr.split("\t")[1:]
        operands = operands.split(", ")

        if mnemonic == "add":
            dest, src = operands
            translation.append(f"{dest.strip()} += {src.strip()};")
        elif mnemonic == "sub":
            dest, src = operands
            translation.append(f"{dest.strip()} -= {src.strip()};")
        elif mnemonic == "mov":
            dest, src = operands
            translation.append(f"{dest.strip()} = {src.strip()};")
        elif mnemonic == "jmp":
            translation.append(f"goto {operands[0].strip()};")
        elif mnemonic == "call":
            translation.append(f"callFunction({operands[0].strip()});")
        elif mnemonic == "ret":
            translation.append("return;")
        elif mnemonic == "nop":
            translation.append("// no operation (nop)")
        elif mnemonic == "cmp":
            dest, src = operands
            translation.append(f"cmp({dest.strip()}, {src.strip()});")
        elif mnemonic == "jg":
            translation.append(f"if (condition > 0) {{ goto {operands[0].strip()}; }}")
        elif mnemonic == "je":
            translation.append(f"if (condition == 0) {{ goto {operands[0].strip()}; }}")
        elif mnemonic == "jne":
            translation.append(f"if (condition != 0) {{ goto {operands[0].strip()}; }}")
        elif mnemonic == "jl":
            translation.append(f"if (condition < 0) {{ goto {operands[0].strip()}; }}")
        elif mnemonic == "push":
            translation.append(f"stack.push({operands[0].strip()});")
        elif mnemonic == "pop":
            translation.append(f"{operands[0].strip()} = stack.pop();")
        elif mnemonic == "enter":
            translation.append(f"setupStackFrame({operands[0].strip()}, {operands[1].strip()});")
        elif mnemonic == "leave":
            translation.append("teardownStackFrame();")
        elif mnemonic == "loopne":
            translation.append(f"if (!zeroFlag) {{ continueLoop({operands[0].strip()}); }}")
        elif mnemonic == "stc":
            translation.append("setCarryFlag();")
        elif mnemonic == "clc":
            translation.append("clearCarryFlag();")
        elif mnemonic == "inc":
            translation.append(f"{operands[0].strip()}++;")
        elif mnemonic == "dec":
            translation.append(f"{operands[0].strip()}--.")
        elif mnemonic == "not":
            translation.append(f"{operands[0].strip()} = ~{operands[0].strip()};")
        elif mnemonic == "xchg":
            translation.append(
                f"{{ {operands[0].strip()} = {operands[1].strip()}; {operands[1].strip()} = {operands[0].strip()}; }}")
        elif mnemonic == "shl":
            translation.append(f"{operands[0].strip()} <<= {operands[1].strip()};")
        elif mnemonic == "shr":
            translation.append(f"{operands[0].strip()} >>= {operands[1].strip()};")
        elif mnemonic == "test":
            translation.append(f"test({operands[0].strip()}, {operands[1].strip()});")
        elif mnemonic == "jae":
            translation.append(f"if (aboveOrEqual) {{ goto {operands[0].strip()}; }}")
        elif mnemonic == "jnp":
            translation.append(f"if (!parityFlag) {{ goto {operands[0].strip()}; }}")
        elif mnemonic == "outsb":
            translation.append(f"outputByte({operands[0].strip()}, {operands[1].strip()});")
        elif mnemonic == "retf":
            translation.append("returnFar();")
        elif mnemonic == "fmul":
            translation.append(f"{operands[0].strip()} *= {operands[1].strip()};")
        elif mnemonic == "std":
            translation.append("setDirectionFlag();")
        else:
            translation.append(f"// Untranslated: {mnemonic} {', '.join(operands)}")

    return translation