# Trace JNI Calls

import sys

from emu.injector import Inject


target = "" # Enter the name of the app to be monitored here.

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[Message from EmuTrace]: {message['payload']}")
    elif message['type'] == 'error':
        print(f"[Error]: {message['stack']}")

def main():
    device, session = Inject(target=target).attach()

    # Load the JNI methods from the file
    with open('jni/libart_jni.txt', 'r') as f:
        jni_methods = f.readlines()

    script_code = """
    var jni_functions = %s;

    function traceJNIFunction(funcName) {
        var addr = Module.findExportByName("libart.so", funcName);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    console.log(funcName + " called.");
    
                    // Check the number of arguments available
                    if (args.length > 0) {
                        // Log the arguments
                        for (var i = 0; i < args.length; i++) {
                            try {
                                console.log("Argument " + i + ": " + args[i].toString());
                            } catch (e) {
                                console.log("Error accessing argument " + i + ": " + e.message);
                            }
                        }
                    } else {
                        console.log("No arguments available.");
                    }
                },
                onLeave: function (retval) {
                    console.log(funcName + " returned " + retval);
                }
            });
        } else {
            console.log("Failed to find " + funcName + " address");
        }
    }
    
    // Iterate over the jni_functions array
    for (var i = 0; i < jni_functions.length; i++) {
        traceJNIFunction(jni_functions[i]);
    }

    jni_functions.forEach(function(func) {
        traceJNIFunction(func.trim());
    });
    """ % (jni_methods)

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()

    print("[*] Tracing JNI functions. Press Ctrl+C to stop.")
    sys.stdin.read()

if __name__ == '__main__':
    main()