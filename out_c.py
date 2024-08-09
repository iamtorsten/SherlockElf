# Convert asm to c code

from asm.asmc       import read_memory_dump, generate_pseudo_c
from utils.utils    import Print_c_Code

file_path = 'bin/memory_dump_0x6e3e80a000_20240807_131049.bin'
code = read_memory_dump(file_path)
address = 0x1000
pseudo_c_code = generate_pseudo_c(code, address)

Print_c_Code(pseudo_c_code)