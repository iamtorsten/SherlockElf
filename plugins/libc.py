# Plugin: Hook strlen
# Description: Hook strlen method

import frida
import sys

from emu.injector import Inject

target = "" # Enter the name of the app to be monitored here.

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[Message from SherlockElf]: {message['payload']}")
        with open("dump/strlen_dump.txt", "a") as f:
            f.write(f'{message}\n')
    elif message['type'] == 'error':
        print(f"[Error]: {message['stack']}")

def on_destroyed():
    print("[*] Script destroyed.")

def main():
    try:
        # Load the script
        with open("hook/strlen.js") as f:
            script_code = f.read()

        # Setup Device, Session and Source
        sherlock = Inject(target=target)
        device, session = sherlock.attach()
        script = sherlock.source(session, script_code)

        script.on('message', on_message)
        script.on('destroyed', on_destroyed)
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
