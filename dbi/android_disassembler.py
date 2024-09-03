# Android Disassembler
# (c) 2024 Torsten Klement, torsten.klinger@googlemail.com
# MIT

import lief

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM


class AndroidDisassembler:
    def __init__(self, disassembly_area, function_list, function_positions):
        self.disassembly_area = disassembly_area
        self.function_list = function_list
        self.function_positions = function_positions
        self.recognized_functions = set()  # Set zur Vermeidung doppelter Funktionen

    def process_file(self, file_path):
        elf = lief.parse(file_path)

        self.insert_text(f"Type: {elf.header.file_type.name}\n", "black")
        self.insert_text(f"Architecture: {elf.header.machine_type.name}\n\n", "black")

        self.insert_text("Libraries:\n", "black")
        for lib in elf.libraries:
            self.insert_text(f"{lib}\n", "black")

        self.insert_text("\nSegments:\n", "black")
        for segment in elf.segments:
            perm = f"{'r' if segment.has(lief.ELF.SEGMENT_FLAGS.R) else '-'}" + \
                   f"{'w' if segment.has(lief.ELF.SEGMENT_FLAGS.W) else '-'}" + \
                   f"{'x' if segment.has(lief.ELF.SEGMENT_FLAGS.X) else '-'}"
            self.insert_text(
                f"{perm}  0x{segment.virtual_address:08x}-0x{segment.virtual_address + segment.virtual_size:08x}\n",
                "black")

        self.insert_text("\n")

        for section in elf.sections:
            section_type = section.type.name if section.type else "UNKNOWN"
            self.insert_text(
                f"0x{section.virtual_address:08x}-0x{section.virtual_address + section.size:08x}  {section.name} ({section_type})  "
                f"{{{'Code' if section.flags == lief.ELF.SECTION_FLAGS.EXECINSTR else 'Read-only data' if section.flags == lief.ELF.SECTION_FLAGS.ALLOC else 'Writable data'}}}\n",
                "black")
            self.insert_text(
                "     " + " ".join(f"{byte:02x}" for byte in section.content[:64]) + "\n",
                "black")

        self.insert_text("\n\n\n")

        # Disassemblieren der .text Sektion
        text_section = elf.get_section(".text")
        if text_section is not None:
            base_address = text_section.virtual_address
            segment_offset = self.get_segment_base_address(elf, base_address)

            code = text_section.content
            md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            md.detail = True

            in_function = False
            current_function_instructions = []
            instructions = list(md.disasm(bytes(code), base_address))

            for i in range(len(instructions)):
                insn = instructions[i]
                current_function_instructions.append(insn)

                if self.is_potential_function_start(insn):
                    if not in_function and current_function_instructions:
                        if current_function_instructions:
                            return_type, args = self.analyze_function_signature(current_function_instructions)
                            function_name = f"sub_{instructions[i - 1].address:x}"

                            # Vermeidung doppelter Funktionen
                            if function_name in self.recognized_functions:
                                continue

                            self.recognized_functions.add(function_name)

                            start_line = self.get_current_index()
                            self.function_positions[function_name] = start_line
                            self.function_list.insert('end', function_name)
                            self.insert_text(
                                f"0x{instructions[i - 1].address:08x} {return_type} {function_name}({', '.join(args)})\n",
                                "function_start")
                            for instr in current_function_instructions:
                                self.insert_text(
                                    f"0x{instr.address:08x}  {' '.join(f'{b:02x}' for b in instr.bytes):<12}  {instr.mnemonic:<7} {instr.op_str}\n",
                                    "asm_code")
                            self.insert_text("\n")

                        in_function = True
                        current_function_instructions = [insn]
                elif insn.mnemonic == "ret":
                    if in_function:
                        return_type, args = self.analyze_function_signature(current_function_instructions)
                        function_name = f"sub_{insn.address:x}"

                        # Vermeidung doppelter Funktionen
                        if function_name in self.recognized_functions:
                            continue

                        self.recognized_functions.add(function_name)

                        start_line = self.get_current_index()
                        self.function_positions[function_name] = start_line
                        self.function_list.insert('end', function_name)
                        self.insert_text(
                            f"0x{insn.address:08x} {return_type} {function_name}({', '.join(args)})\n",
                            "function_start")
                        for instr in current_function_instructions:
                            self.insert_text(
                                f"0x{instr.address:08x}  {' '.join(f'{b:02x}' for b in instr.bytes):<12}  {instr.mnemonic:<7} {instr.op_str}\n",
                                "asm_code")
                        self.insert_text("\n")

                    in_function = False
                    current_function_instructions = []

    def analyze_function_signature(self, instructions):
        args = []
        return_type = "void"

        arg_registers = ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7']
        register_to_type = {reg: None for reg in arg_registers}

        for insn in instructions:
            if insn.mnemonic == 'mov' and insn.op_str == 'x0':
                return_type = "int"
            elif insn.mnemonic == 'ldr' and 'x0' in insn.op_str:
                return_type = "pointer"

            for reg in arg_registers:
                if reg in insn.op_str:
                    if 'ldr' in insn.mnemonic:
                        register_to_type[reg] = "pointer"
                    elif 'mov' in insn.mnemonic or 'add' in insn.mnemonic:
                        register_to_type[reg] = "int32_t"
                    elif 'str' in insn.mnemonic:
                        register_to_type[reg] = "int32_t*"

        for reg in arg_registers:
            reg_type = register_to_type[reg]
            if reg_type:
                args.append(f"{reg_type} arg{arg_registers.index(reg) + 1}")

        if not args:
            args.append("void")

        return return_type, args

    def get_segment_base_address(self, elf, section_va):
        for segment in elf.segments:
            if segment.virtual_address <= section_va < (segment.virtual_address + segment.virtual_size):
                return segment.virtual_address
        return 0

    def is_potential_function_start(self, insn):
        if insn.mnemonic in {'bl', 'blr', 'b', 'br', 'cbz', 'cbnz', 'tbnz', 'tbz'}:
            return True
        if insn.mnemonic == 'adrp' and ('x' in insn.op_str):
            return True
        if insn.mnemonic == 'stp' and ('x29, x30' in insn.op_str):
            return True
        return False

    def insert_text(self, text, tag=None):
        self.disassembly_area.insert('end', text, tag)

    def get_current_index(self):
        return self.disassembly_area.index('end')
