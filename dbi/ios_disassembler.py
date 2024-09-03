# iOS Disassembler
# (c) 2024 Torsten Klement, torsten.klinger@googlemail.com
# MIT

import lief

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

class IOSDisassembler:
    def __init__(self, disassembly_area, function_list, function_positions):
        self.disassembly_area = disassembly_area
        self.function_list = function_list
        self.function_positions = function_positions
        self.recognized_functions = set()

    def process_file(self, file_path):
        binary = lief.parse(file_path)

        if isinstance(binary, lief.MachO.FatBinary):
            self.insert_text("This is a FatBinary containing multiple architectures.\n\n", "black")
            for macho in binary:
                self.insert_text(f"Architecture: {macho.header.cpu_type}\n", "black")
                self.process_macho(macho)
        elif isinstance(binary, lief.MachO.Binary):
            self.process_macho(binary)
        else:
            self.insert_text("Unsupported file type or format.\n", "black")

    def process_macho(self, macho):
        self.insert_text(f"Type: {macho.header.file_type.name}\n", "black")
        self.insert_text(f"Architecture: {macho.header.cpu_type.name}\n\n", "black")

        # Libraries anzeigen in schwarz
        self.insert_text("Libraries:\n", "black")
        for lib in macho.libraries:
            self.insert_text(f"{lib.name}\n", "black")

        self.insert_text("\nSegments:\n", "black")
        for segment in macho.segments:
            self.insert_text(
                f"{segment.name}: 0x{segment.virtual_address:08x}-0x{segment.virtual_address + segment.virtual_size:08x}\n",
                "black")

        # Sections
        self.insert_text("\nSections:\n", "black")
        for section in macho.sections:
            self.insert_text(f"0x{section.virtual_address:08x}-0x{section.virtual_address + section.size:08x}  {section.name} ({section.type})\n", "black")
            self.insert_text("     " + " ".join(f"{byte:02x}" for byte in section.content[:64]) + "\n", "black")

        # Suche nach der .text Sektion
        text_section = macho.get_section("__text")
        if text_section:
            self.insert_text(f"\nDisassembling __text section at 0x{text_section.virtual_address:08x}\n\n", "black")
            self.disassemble_text_section(text_section)
        else:
            self.insert_text("\n.text section not found.\n", "black")

    def disassemble_text_section(self, text_section):
        code = text_section.content
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        md.detail = True

        in_function = False
        current_function_instructions = []
        instructions = list(md.disasm(bytes(code), text_section.virtual_address))

        for i in range(len(instructions)):
            insn = instructions[i]
            current_function_instructions.append(insn)

            if self.is_potential_function_start(insn):
                if in_function:
                    self.recognize_function(current_function_instructions)
                in_function = True
                current_function_instructions = [insn]

            if self.is_potential_function_end(insn):
                if in_function:
                    self.recognize_function(current_function_instructions)
                in_function = False
                current_function_instructions = []

        if in_function and current_function_instructions:
            self.recognize_function(current_function_instructions)

    def recognize_function(self, instructions):
        if not instructions:
            return

        function_name = f"sub_{instructions[0].address:x}"
        if function_name in self.recognized_functions:
            return  # Skip already recognized function

        return_type, args = self.analyze_function_signature(instructions)
        start_line = self.disassembly_area.index('end')
        self.function_positions[function_name] = start_line
        self.function_list.insert('end', function_name)
        self.recognized_functions.add(function_name)

        self.insert_text(f"0x{instructions[0].address:08x} {return_type} {function_name}({', '.join(args)})\n", "function_start")
        for instr in instructions:
            self.insert_text(f"0x{instr.address:08x}  {' '.join(f'{b:02x}' for b in instr.bytes):<12}  {instr.mnemonic:<7} {instr.op_str}\n", "asm_code")
        self.insert_text("\n")

    def is_potential_function_start(self, insn):
        # Überprüfung auf typische Prolog- und Setup-Instruktionen
        if insn.mnemonic in {'stp'} and ('x29, x30' in insn.op_str or 'x28, x27' in insn.op_str):
            return True
        if insn.mnemonic == 'sub' and 'sp, sp' in insn.op_str:
            return True
        if insn.mnemonic == 'adrp' or (insn.mnemonic == 'mov' and 'sp,' in insn.op_str):
            return True
        if insn.mnemonic == 'bl' and 'x' in insn.op_str:
            return True

        # Weitere Heuristiken für ARM64
        if insn.mnemonic == 'ldr' and 'x29' in insn.op_str:
            return True
        if insn.mnemonic == 'str' and 'x30' in insn.op_str:
            return True
        if insn.mnemonic == 'add' and 'sp, sp' in insn.op_str:
            return True
        if insn.mnemonic == 'mov' and 'x29,' in insn.op_str and 'sp' in insn.op_str:
            return True

        return False

    def is_potential_function_end(self, insn):
        # Überprüfung auf typische Epilog-Instruktionen
        if insn.mnemonic in {'ret', 'ldp', 'b'}:
            if insn.mnemonic == 'ldp' and ('x29, x30' in insn.op_str or 'x28, x27' in insn.op_str):
                return True
            if insn.mnemonic == 'ret':
                return True
            if insn.mnemonic == 'b' and not insn.op_str.startswith('sub_'):
                return True

        # Weitere Heuristiken für ARM64
        if insn.mnemonic == 'add' and 'sp, sp' in insn.op_str:
            return True
        if insn.mnemonic == 'ldr' and 'x30' in insn.op_str:
            return True
        if insn.mnemonic == 'br' and 'x30' in insn.op_str:
            return True

        return False

    def analyze_function_signature(self, instructions):
        args = []
        return_type = "void"

        for insn in instructions:
            if insn.mnemonic == 'mov' and 'x0' in insn.op_str:
                return_type = "int"
            if insn.mnemonic == 'ldr' and 'x0' in insn.op_str:
                return_type = "pointer"
            if 'x1' in insn.op_str:
                args.append("int64_t arg1")
            if 'x2' in insn.op_str:
                args.append("int64_t arg2")
            if 'x3' in insn.op_str:
                args.append("int64_t arg3")
            if 'x4' in insn.op_str:
                args.append("int64_t arg4")
            if 'x5' in insn.op_str:
                args.append("int64_t arg5")
            if 'x6' in insn.op_str:
                args.append("int64_t* arg6")

        if not args:
            args.append("void")

        return return_type, args

    def insert_text(self, text, tag=None):
        self.disassembly_area.insert('end', text, tag)
