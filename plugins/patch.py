# Plugin: Patch Functions
# Description: Script zum Patchen von Funktionen oder Adressen innerhalb einer nativen Android Library

import sys

from emu.injector import Inject


# JavaScript Code zum Patchen der Funktion an einer bestimmten Adresse
def generate_js_code(target_library, patches):
    js_code = f"""
    const targetLibrary = Module.getBaseAddress("{target_library}");
    """

    for patch in patches:
        address = patch["address"]
        instructions = patch.get("instructions", [])
        full_address = f"targetLibrary.add({address})"

        js_code += f"""
        Interceptor.attach({full_address}, {{
            onEnter: function (args) {{
                console.log("[INFO] Hooking Instruction at Address: {full_address}");

        """

        for instruction in instructions:
            original = instruction.get("original")
            replacement = instruction.get("replace")

            # Patchen von Registeroperationen (z.B. mov, add, sub)
            if "mov" in original:
                reg = original.split()[1].strip(",")  # z.B. x0 bei "mov x0, x1"
                js_code += f"""
                var original_value = this.context.{reg};
                console.log("[INFO] Originalwert von {reg}: " + original_value);

                // Patchen des Registers {reg}
                this.context.{reg} = ptr("{replacement}");
                console.log("[INFO] Geänderter Wert von {reg}: " + this.context.{reg});
                """

            elif "add" in original:
                reg = original.split()[1].strip(",")
                js_code += f"""
                var original_value = this.context.{reg}.toInt32();
                console.log("[INFO] Originalwert von {reg}: " + original_value);

                // Addieren eines Werts zu {reg}
                this.context.{reg} = ptr(original_value + {replacement});
                console.log("[INFO] Geänderter Wert von {reg}: " + this.context.{reg});
                """

            elif "sub" in original:
                reg = original.split()[1].strip(",")
                js_code += f"""
                var original_value = this.context.{reg}.toInt32();
                console.log("[INFO] Originalwert von {reg}: " + original_value);

                // Subtrahieren eines Werts von {reg}
                this.context.{reg} = ptr(original_value - {replacement});
                console.log("[INFO] Geänderter Wert von {reg}: " + this.context.{reg});
                """

            # Patchen von Speicheroperationen (z.B. ldr, str)
            elif "ldr" in original or "str" in original:
                reg = original.split()[1].strip(",")  # Register, in das geladen wird oder aus dem gespeichert wird
                js_code += f"""
                var mem_address = this.context.{reg};
                console.log("[INFO] Speicheradresse, die gepatcht wird: " + mem_address);

                // Patchen des Werts an der Speicheradresse
                Memory.writePointer(mem_address, ptr("{replacement}"));
                console.log("[INFO] Neuer Wert an Speicheradresse: " + Memory.readPointer(mem_address));
                """

        js_code += """
            }},
            onLeave: function (retval) {{
                console.log("[INFO] Rückgabewert vor dem Patch: " + retval.toInt32());
        """

        if "return" in patch:
            new_retval = patch["return"]
            js_code += f"""
                retval.replace({new_retval});
                console.log("[INFO] Rückgabewert nach dem Patch: " + retval.toInt32());
            """

        js_code += """
            }}
        }});
        """

    return js_code

# Python Funktion um die Session zu starten und die JS-Skripte zu laden
def patch_functions_in_library(target, target_library, patches):
    # Setup Device, Session and Source
    sherlock = Inject(target=target)
    device, session = sherlock.attach()
    # Generiere das JavaScript für alle Patches
    js_code = generate_js_code(target_library, patches)
    script = sherlock.source(session, js_code)

    script.on('message', on_message)
    script.load()
    print(f"[INFO] Alle Patches wurden geladen für Library {target_library}.")

    sys.stdin.read()  # Halte das Skript am Laufen

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    elif message['type'] == 'error':
        print("[!] {0}".format(message['stack']))

# Beispiel-Logik zur Verwendung der Funktionen
if __name__ == "__main__":
    target_process = ""
    target_library = ""  # Name der zu patchenden Library

    # Beispielhafte Patches
    patches = [
        {
            "address": "0x1ea8",  # Adresse relativ zur Basis der Library
            "instructions": [
                {"original": "mov x0, x1", "replace": "0x12345678"},  # Setzt x0 auf 0x12345678
                {"original": "ldr x0, [x1]", "replace": "0x87654321"},  # Lädt 0x87654321 in x0
            ],
            "return": "0x9999"  # Optional: Rückgabewert ändern
        },
        {
            "address": "0xf000",  # Adresse relativ zur Basis der Library
            "instructions": [
                {"original": "add x0, #0x10", "replace": "0x20"},  # Addiert 0x20 zu x0 anstelle von 0x10
                {"original": "str x0, [x1]", "replace": "0x55555555"}  # Speichert 0x55555555 in der Adresse in x1
            ]
        },
        {
            "address": "0xf004",  # Adresse relativ zur Basis der Library
            "instructions": [
                {"original": "sub sp, #0x10", "replace": "0x20"},  # Subtrahiert 0x20 von sp statt 0x10
                {"original": "ldr x2, [x3]", "replace": "0x33333333"},  # Lädt 0x33333333 in x2
            ]
        }
    ]

    patch_functions_in_library(target_process, target_library, patches)
