# Plugin: libart jni
# Description: List libart jni

import frida
import sys

from emu.injector import Inject

target = "" # Enter the name of the app to be monitored here.
script_file = "hook/libart.js"  # Hook


def main():
    try:
        # Load the script
        with open(script_file) as f:
            script_code = f.read()

        # Setup Device, Session and Source
        sherlock = Inject(target=target)
        device, session = sherlock.attach()
        script = sherlock.source(session, script_code)

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
