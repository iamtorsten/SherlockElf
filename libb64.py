# Hook base64

import frida
import sys

from emu.injector import Inject

target = "" # Enter the name of the app to be monitored here.
script_file = "hook/b64.js"  # Hook

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        if 'function' in payload:
            print(f"[{payload['function']}] {payload}")
        elif 'success' in payload:
            print(f"[Success] {payload['success']}")
        elif 'error' in payload:
            print(f"[Error] {payload['error']}")
    elif message['type'] == 'error':
        print(f"[Script Error] {message['stack']}")

def main():
    try:
        # Load the Frida script
        with open(script_file) as f:
            script_code = f.read()

        # Setup Device, Session and Source
        sherlock = Inject(target=target)
        device, session = sherlock.attach()
        script = sherlock.source(session, script_code)

        script.on('message', on_message)
        script.load()

        # Keep the script running
        print(f"[*] Hooking {target}. Press Ctrl+C to stop.")
        sys.stdin.read()
    except frida.ServerNotRunningError:
        print("SherlockElf server is not running. Please start the SherlockElf Server on your device.")
    except frida.ProcessNotFoundError:
        print(f"Process '{target}' not found. Make sure the app is running.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()