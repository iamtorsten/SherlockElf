# Convert asm to py code

from asm.asmpy import load_binary_file, disassemble_code, translate_to_python
from utils.utils import Print_py_Code

filename = "bin/memory_dump_0x6e3e80a000_20240807_131053.bin"
binary_code = load_binary_file(filename)

asm_instructions = disassemble_code(binary_code)
python_code = translate_to_python(asm_instructions)

for line in python_code:
    Print_py_Code(line)