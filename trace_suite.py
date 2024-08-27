# Trace Function Flow, Register Values, Code Execution and Return Values
# of Android Native Libraries
# (c) 2024 Torsten Klement, torsten.klinger@googlemail.com
# MIT

import codecs
import os
import frida
import sys

from datetime           import datetime
from colorama           import Fore
from emu.injector       import Inject
from emu.trace_native   import load_script


def Print(text: str):
    print(
        f"{Fore.LIGHTBLUE_EX}{Fore.LIGHTCYAN_EX}{text}{Fore.LIGHTBLUE_EX}{Fore.RESET}")

banner = """
  ___ _            _         _   ___ _  __   _____                  ___      _ _       
 / __| |_  ___ _ _| |___  __| |_| __| |/ _| |_   _| _ __ _ __ ___  / __|_  _(_) |_ ___ 
 \__ \ ' \/ -_) '_| / _ \/ _| / / _|| |  _|   | || '_/ _` / _/ -_) \__ \ || | |  _/ -_)
 |___/_||_\___|_| |_\___/\__|_\_\___|_|_|     |_||_| \__,_\__\___| |___/\_,_|_|\__\___| \n\n(c) 2024 - now Torsten Klement\nContact [Skype]: https://join.skype.com/invite/ErVkPMTQZExQ\nContact [Telegram]: https://t.me/iamtorsten
"""

Print(banner)

# Target Application
target = ""
# Target Library
target_library = ""
# Directory to save the output files
output_dir = "trace_suite_output"
os.makedirs(output_dir, exist_ok=True)  # Create the directory if it doesn't exist
os.makedirs(f"{output_dir}/{target}/{target_library.replace('.', '_')}", exist_ok=True)  # Create the directory if it doesn't exist
# Hooked functions
functions = [
    {"offset": 0xebea8, "name": "FunctionA"}  # Add pseudo names for clarity
    # Add more functions with their offsets and names as needed
]
# Create directories for each function based on their pseudo name
for function in functions:
    os.makedirs(f"{output_dir}/{target}/{target_library.replace('.', '_')}/{function['name']}", exist_ok=True) # Create the directory if it doesn't exist
# Maximal Assembly Instructions per function
# As soon as the script has recognized the last instruction, it stops and displays a message
max_instructions = 250


def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        if isinstance(payload, dict):
            function_name = payload.get("function_name", "unknown")
            function_offset = payload.get("function_offset", "unknown")
            file_name = f'trace_suite_output.txt'
            file_path = f'{output_dir}/{target}/{target_library.replace(".", "_")}/{function_name}/{file_name}'

            with codecs.open(file_path, "a", "utf-8") as f:  # Use UTF-8 encoding
                event = payload.get("event")
                if event == "onEnter":
                    type = "Function Entry - Register Values"
                    f.write(f"[ {datetime.now()} ]\n")
                    f.write(f">>> {type} <<<\n")
                    registers = payload.get("registers", {})
                    for reg, values in registers.items():
                        f.write(f"{reg}:\n")
                        for key, value in values.items():
                            f.write(f"  {key}: {value}\n")
                elif event == "onLeave":
                    type = "Function Exit - Register and Return Values"
                    f.write(f">>> {type} <<<\n")
                    registers = payload.get("registers", {})
                    for reg, values in registers.items():
                        f.write(f"{reg}:\n")
                        for key, value in values.items():
                            f.write(f"  {key}: {value}\n")
                    f.write(f"Return Value: {payload.get('retval')}\n\n")
                elif event == "instruction":
                    address = payload.get("address")
                    mnemonic = payload.get("mnemonic")
                    opStr = payload.get("opStr")
                    type = f"Instruction: {address}: {mnemonic} {opStr}"
                    f.write(f"Instruction: {address}: {mnemonic} {opStr}\n")

                    # Detect instructions that involve memory access
                    if "ptr [" in opStr:
                        # Send this instruction back to the JavaScript code for memory value extraction
                        mem_access = opStr.split("ptr [")[1].split("]")[0]
                        type = f"Memory Access Pattern: {mem_access}"
                        f.write(f"Memory Access Pattern: {mem_access}\n")
                        # We don't do any evaluation here; it's handled in the JS code
                elif event == "registerChange":
                    type = "Register Changes Detected"
                    f.write(f">>> {type} <<<\n")
                    changes = payload.get("changes", {})
                    for reg, change in changes.items():
                        f.write(f"{reg}:\n")
                        f.write("  Before:\n")
                        for key, value in change["before"].items():
                            f.write(f"    {key}: {value}\n")
                        f.write("  After:\n")
                        for key, value in change["after"].items():
                            f.write(f"    {key}: {value}\n")
            print(f"[INFO] Data written to {file_name}. Type: {type}")
    elif message['type'] == 'error':
        print(f"[ERROR] An error occurred: {message['stack']}")


def main():
    try:
        # Load the script
        script_code = load_script(target_library, functions, max_instructions)

        # Setup Device, Session and Source
        sherlock = Inject(target=target)
        device, session = sherlock.attach()
        script = sherlock.source(session, script_code)

        script.on('message', on_message)
        script.load()

        # Keep the script running
        print(
            f"[*] SherlockElf Trace Suite [ -> {target} -> {target_library} -> {functions} ]: Monitoring started. Press Ctrl+C to stop.")
        sys.stdin.read()
    except frida.ServerNotRunningError:
        print("SherlockElf server is not running. Please start the SherlockElf Server on your device.")
    except frida.ProcessNotFoundError:
        print(f"Process '{target}' not found. Make sure the app is running.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()