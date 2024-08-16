// Function hook
// (c) Torsten Klement

rpc.exports = {
    hookfunction: function(functionOffset, moduleName) {
        console.log("Starting script to hook function at offset 0x" + functionOffset.toString(16) + " in " + moduleName + "...");

        var module = Process.findModuleByName(moduleName);

        if (module) {
            console.log("Module found: " + moduleName);
            var baseAddress = module.base;
            console.log("Base address of " + moduleName + ": " + baseAddress);

            // Calculate the target address by adding the offset to the base address
            var targetAddress = baseAddress.add(ptr(functionOffset));
            console.log("Calculated target address: " + targetAddress);

            // Hook the function at the calculated address
            Interceptor.attach(targetAddress, {
                onEnter: function(args) {
                    var logMessage = "Function at " + targetAddress + " called.\n";
                    var maxRegisters = 10; // Max registers to check for arguments (x0 to x9)
                    for (var i = 0; i < maxRegisters; i++) {
                        var regName = "x" + i;
                        var regValue = this.context[regName];

                        if (regValue !== undefined) {
                            logMessage += regName + " (arg" + (i + 1) + "): " + regValue.toString() + "\n";

                            // Attempt to decode the argument as an integer
                            try {
                                var intValue = regValue.toInt32();
                                logMessage += regName + " as int: " + intValue + "\n";
                            } catch (e) {
                                logMessage += regName + " could not be decoded as an int.\n";
                            }

                            // Attempt to decode the argument as a string
                            try {
                                var possibleString = regValue.readUtf8String();
                                logMessage += regName + " as string: " + possibleString + "\n";
                            } catch (e) {
                                logMessage += regName + " is not a readable string.\n";
                            }
                        }
                    }
                    console.log(logMessage);  // Log to console
                    send(logMessage); // Send the log message to the Python script
                },
                onLeave: function(retval) {
                    var logMessage = "Function at " + targetAddress + " returned: " + retval.toString() + "\n";

                    // Attempt to decode the return value as an integer
                    try {
                        var retIntValue = retval.toInt32();
                        logMessage += "Return value as int: " + retIntValue + "\n";
                    } catch (e) {
                        logMessage += "Return value could not be decoded as an int.\n";
                    }

                    // Attempt to decode the return value as a string
                    try {
                        var retString = retval.readUtf8String();
                        logMessage += "Return value as string: " + retString + "\n";
                    } catch (e) {
                        logMessage += "Return value is not a readable string.\n";
                    }

                    console.log(logMessage);  // Log to console
                    send(logMessage); // Send the log message to the Python script
                }
            });

        } else {
            console.log("Module not found: " + moduleName);
        }
    }
};
