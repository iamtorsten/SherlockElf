# Plugin: Hook Function
# Description: Hooks a function inside a native library

import sys
from emu.injector import Inject
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

# Callback function to receive messages from script
def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])  # Print to console
        # Use 'utf-8' encoding to handle a wide range of characters
        with open("dump/func_dump.txt", "a", encoding="utf-8") as f:
            f.write(message['payload'] + "\n")
    elif message['type'] == 'error':
        print("[!] Error: {0}".format(message['stack']))


target = "TikTok"
function_offset = 0x2944
module_name = "libdelta.so"

# Load the JavaScript file
with open("hook/func.js", "r") as f:
    script_code = f.read()

# Setup Device, Session and Source
sherlock = Inject(target=target)
device, session = sherlock.attach()
script = sherlock.source(session, script_code)

script.on('message', on_message)
script.load()
script.exports.hookfunction(function_offset, module_name)
input("Press Enter to exit...\n")
sys.stdin.read()