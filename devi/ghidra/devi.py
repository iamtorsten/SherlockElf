# Devirtualisieren von virtuellen Funktionsaufrufen in Assembly
# (c) 2024 Torsten Klement, torsten.klinger@googlemail.com
# MIT

"""
Ghidra-spezifische API: Das Skript verwendet nur die Ghidra-internen Funktionen und Klassen,
die in der Jython-Umgebung von Ghidra verfügbar sind. Es ist dafür ausgelegt, direkt in Ghidra
ausgeführt zu werden.

Ausführen des Skripts in Ghidra:

1. Öffne Ghidra und lade das zu analysierende Projekt.
2. Gehe zu Window -> Script Manager.
3. Erstelle ein neues Skript oder öffne ein existierendes Skript in Python/Jython.
4. Kopiere das obige Skript in das Skriptfenster und führe es aus.
"""

from ghidra.program.model.symbol import RefType
from ghidra.program.model.data import PointerDataType
from ghidra.app.decompiler import DecompInterface


def get_decompiler():
    """Setup the decompiler interface for future use."""
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    return decomp


def analyze_vtable(pointer):
    """
    Analyze a VTable starting from the given pointer address.
    This function attempts to identify function pointers within a VTable.
    """
    vtable_entries = []
    address = pointer

    # Iterate through possible VTable entries
    while True:
        func_ptr = getDataAt(address)
        if func_ptr is None or not isinstance(func_ptr.getDataType(), PointerDataType):
            break

        target_func = getFunctionAt(func_ptr.getValue())
        if target_func is not None:
            vtable_entries.append(target_func)
        else:
            print(f"Warning: No function found at {func_ptr.getValue()} - possibly an invalid VTable entry.")

        address = address.add(8)  # Assuming 64-bit architecture. Adjust if necessary.

    if not vtable_entries:
        print(f"Warning: No VTable entries found at {pointer}")

    return vtable_entries


def trace_back_to_vtable(inst):
    """
    Trace back from a computed call instruction to determine if it's based on a VTable entry.
    """
    previous = inst.getPrevious()
    while previous:
        if previous.getMnemonicString() in ["MOV", "LEA"]:
            vtable_pointer = previous.getOpObjects(1)[0]
            if isinstance(vtable_pointer, ghidra.program.model.address.Address):
                return vtable_pointer
        previous = previous.getPrevious()
    return None


def analyze_virtual_call(call_inst):
    """
    Analyze a computed virtual call to devirtualize it.
    """
    try:
        vtable_pointer = trace_back_to_vtable(call_inst)
        if vtable_pointer:
            vtable_funcs = analyze_vtable(vtable_pointer)
            if vtable_funcs:
                # Assume the first entry corresponds to our call (this might need adjustments)
                target_func = vtable_funcs[0]
                print(f"Devirtualized target function: {target_func.getName()} at {target_func.getEntryPoint()}")
                return target_func
            else:
                print(f"Error: VTable at {vtable_pointer} appears to be empty.")
        else:
            print("Error: Could not trace back to a valid VTable.")
    except Exception as e:
        print(f"Exception during analysis: {str(e)}")
    return None


def devirtualize_virtual_calls():
    """
    Main function to devirtualize virtual calls in the current program.
    """
    listing = currentProgram.getListing()
    functions = listing.getFunctions(True)

    for function in functions:
        references = function.getReferencesFrom()

        for ref in references:
            if ref.getReferenceType() == RefType.COMPUTED_CALL:
                call_inst = getInstructionAt(ref.getFromAddress())
                if call_inst:
                    print(f"Virtual call found at address: {ref.getFromAddress()} in function: {function.getName()}")
                    devirtualized_func = analyze_virtual_call(call_inst)
                    if not devirtualized_func:
                        print("  -> Could not devirtualize the call.")
                else:
                    print(f"Error: Instruction not found at address: {ref.getFromAddress()}")


# Ghidra decompiler for potential further use
decompiler = get_decompiler()

# Run the devirtualization process
devirtualize_virtual_calls()
