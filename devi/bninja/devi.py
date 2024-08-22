# Devirtualisieren von virtuellen Funktionsaufrufen in Assembly
# (c) 2024 Torsten Klement, torsten.klinger@googlemail.com
# MIT

"""
You can use this script directly within Binary Ninja's script editor or as part of a plugin.
"""

from binaryninja import BinaryView, InstructionTextToken, Function, LowLevelILOperation, log_info, log_error
from binaryninja.enums import InstructionTextTokenType

def analyze_vtable(bv: BinaryView, pointer):
    """
    Analyze a VTable starting from the given pointer address.
    This function attempts to identify function pointers within a VTable.
    """
    vtable_entries = []
    address = pointer

    # Iterate through possible VTable entries
    while True:
        func_ptr = bv.get_data_var_at(address).value if bv.is_valid_offset(address) else None
        if func_ptr is None or not bv.get_function_at(func_ptr):
            break

        target_func = bv.get_function_at(func_ptr)
        if target_func is not None:
            vtable_entries.append(target_func)
        else:
            log_error(f"Warning: No function found at {func_ptr} - possibly an invalid VTable entry.")

        address += bv.address_size  # Adjust for architecture (4 bytes for 32-bit, 8 bytes for 64-bit)

    if not vtable_entries:
        log_error(f"Warning: No VTable entries found at {pointer}")

    return vtable_entries

def trace_back_to_vtable(bv: BinaryView, func: Function, inst_addr):
    """
    Trace back from a computed call instruction to determine if it's based on a VTable entry.
    """
    il = func.get_low_level_il_at(inst_addr)
    if not il:
        return None

    while il:
        if il.operation in {LowLevelILOperation.LLIL_LOAD, LowLevelILOperation.LLIL_ADD}:
            vtable_pointer = il.src
            if vtable_pointer.operation == LowLevelILOperation.LLIL_CONST_PTR:
                return vtable_pointer.constant
        il = il.il_basic_block.get_instruction_start(il.instr_index - 1)

    return None

def analyze_virtual_call(bv: BinaryView, func: Function, inst_addr):
    """
    Analyze a computed virtual call to devirtualize it.
    """
    try:
        vtable_pointer = trace_back_to_vtable(bv, func, inst_addr)
        if vtable_pointer:
            vtable_funcs = analyze_vtable(bv, vtable_pointer)
            if vtable_funcs:
                # Assume the first entry corresponds to our call (this might need adjustments)
                target_func = vtable_funcs[0]
                log_info(f"Devirtualized target function: {target_func.name} at {hex(target_func.start)}")
                return target_func
            else:
                log_error(f"Error: VTable at {hex(vtable_pointer)} appears to be empty.")
        else:
            log_error("Error: Could not trace back to a valid VTable.")
    except Exception as e:
        log_error(f"Exception during analysis: {str(e)}")
    return None

def devirtualize_virtual_calls(bv: BinaryView):
    """
    Main function to devirtualize virtual calls in the current program.
    """
    for func in bv.functions:
        for ref in func.call_sites:
            call_inst = ref.address
            if call_inst:
                log_info(f"Virtual call found at address: {hex(call_inst)} in function: {func.name}")
                devirtualized_func = analyze_virtual_call(bv, func, call_inst)
                if not devirtualized_func:
                    log_error("  -> Could not devirtualize the call.")
            else:
                log_error(f"Error: Instruction not found at address: {hex(ref.address)}")

# Run the devirtualization process
bv = BinaryView()  # Replace with the appropriate BinaryView if running within a plugin or script
devirtualize_virtual_calls(bv)