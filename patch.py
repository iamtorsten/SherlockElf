# Script zum Patchen von Funktionen oder Adressen innerhalb einer
# nativen Android Library

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

        # Hier werden die Adressen relativ zur Basisadresse der Library gesetzt
        full_address = f"targetLibrary.add({address})"

        js_code += f"""
        Interceptor.attach({full_address}, {{
            onEnter: function (args) {{
                console.log("[INFO] Hooking Instruction at Address: {full_address}");

                // Instruktionen patchen
        """

        for instruction in instructions:
            if "replace" in instruction:
                original = instruction["original"]
                replacement = instruction["replace"]
                js_code += f"""
                if (this.context.{original}) {{
                    console.log("[INFO] {original} gepatched.");
                    this.context.{original} = ptr("{replacement}");
                }}
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
                {"original": "x16", "replace": "0x12345678"}  # Original Register wird durch neuen Wert ersetzt
            ]
        },
        {
            "address": "0xf000",  # Adresse relativ zur Basis der Library
            "instructions": [
                {"original": "sp", "replace": "sp.sub(0x20)"}  # Subtrahiere 0x20 statt 0x10 vom Stack Pointer
            ]
        },
        {
            "address": "0xf004",  # Adresse relativ zur Basis der Library
            "instructions": [
                {"original": "q30", "replace": "0x11111111"},
                {"original": "q31", "replace": "0x22222222"}
            ],
            "return": "0x9999"  # Optional: Rückgabewert ändern
        }
    ]

    patch_functions_in_library(target_process, target_library, patches)
