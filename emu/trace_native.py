def load_script(target_library, functions, max_instructions):
    hooks = []
    for function in functions:
        offset = function["offset"]
        name = function["name"]
        hook = f"""
        {{
            const targetLibrary = "{target_library}";
            const targetFunctionOffset = {offset};
            var maxInstructions = {max_instructions};

            function hexToString(hex) {{
                try {{
                    return Memory.readUtf8String(ptr(hex));
                }} catch (e) {{
                    return "N/A";
                }}
            }}

            function hexToInt(hex) {{
                try {{
                    return parseInt(hex, 16);
                }} catch (e) {{
                    return "N/A";
                }}
            }}

            function hexToByteArray(hex) {{
                try {{
                    var byteArray = Memory.readByteArray(ptr(hex), 16);
                    if (byteArray) {{
                        var bytes = new Uint8Array(byteArray);
                        return Array.from(bytes).map(b => '0x' + b.toString(16).padStart(2, '0'));
                    }} else {{
                        return "N/A";
                    }}
                }} catch (e) {{
                    return "N/A";
                }}
            }}

            function getRegisterInfo(context) {{
                var registerNames = [
                    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
                    "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19",
                    "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
                    "sp", "pc"
                ];

                var registers = {{}};

                registerNames.forEach(function(name) {{
                    if (context[name] !== undefined) {{
                        var value = context[name].toString(16);
                        registers[name] = {{
                            "hex": "0x" + value,
                            "string": hexToString(context[name]),
                            "int": hexToInt(context[name].toString()),
                            "bytes": hexToByteArray(context[name].toString())
                        }};
                    }} else {{
                        registers[name] = {{
                            "hex": "N/A",
                            "string": "N/A",
                            "int": "N/A",
                            "bytes": "N/A"
                        }};
                    }}
                }});

                return registers;
            }}

            function detectRegisterChanges(previous, current) {{
                var changes = {{}};
                for (var reg in current) {{
                    if (previous[reg].hex !== current[reg].hex) {{
                        changes[reg] = {{
                            "before": previous[reg],
                            "after": current[reg]
                        }};
                    }}
                }}
                return changes;
            }}

            function evaluateMemoryAccess(context, mem_access) {{
                // Evaluate the memory access pattern
                try {{
                    var address = eval(mem_access);
                    return ptr(address).readPointer();
                }} catch (e) {{
                    return "N/A";
                }}
            }}

            function traceInstructions(startAddress, registers) {{
                var currentAddress = startAddress;

                for (var i = 0; i < maxInstructions; i++) {{
                    try {{
                        var instruction = Instruction.parse(currentAddress);
                        send({{
                            "event": "instruction",
                            "address": currentAddress.toString(),
                            "mnemonic": instruction.mnemonic,
                            "opStr": instruction.opStr,
                            "function_name": "{name}",
                            "function_offset": "{hex(offset)}"
                        }});

                        console.log("[INFO] Processing instruction: " + instruction.opStr);

                        if (instruction.mnemonic === "br" || instruction.mnemonic === "bl") {{
                            var targetReg = instruction.opStr.trim();  // Directly use the opStr for branch instructions

                            if (targetReg && registers[targetReg] && registers[targetReg].hex) {{
                                console.log("[INFO] Found target register " + targetReg + " with value: " + registers[targetReg].hex);
                                currentAddress = ptr(registers[targetReg].hex);
                                console.log("[INFO] Following branch to address: " + currentAddress);
                            }} else {{
                                console.log("[WARNING] Branch target register " + targetReg + " not found or improperly formatted. Registers available: " + JSON.stringify(registers));
                                break;
                            }}
                        }} else if (instruction.mnemonic === "ret") {{
                            console.log("[INFO] Return instruction encountered, ending trace");
                            break;
                        }} else {{
                            currentAddress = currentAddress.add(instruction.size);
                        }}

                    }} catch (e) {{
                        console.log("[WARNING] Invalid instruction at " + currentAddress + ": " + e.message);
                        break;
                    }}
                }}
            }}

            function hookFunction(libraryName, offset, functionName) {{
                var module = Process.getModuleByName(libraryName);
                var functionAddress = module.base.add(offset);

                console.log("[INFO] Hooking function at address: " + functionAddress);

                try {{
                    Interceptor.attach(functionAddress, {{
                        onEnter: function(args) {{
                            console.log("[INFO] Function entered at address: " + functionAddress);

                            var registers = getRegisterInfo(this.context);
                            var registerOutput = {{
                                "event": "onEnter",
                                "registers": registers,
                                "function_name": functionName,
                                "function_offset": "{hex(offset)}"
                            }};
                            send(registerOutput);

                            traceInstructions(this.context.pc, registers);
                        }},
                        onLeave: function(retval) {{
                            var registers = getRegisterInfo(this.context);
                            var registerOutput = {{
                                "event": "onLeave",
                                "registers": registers,
                                "retval": retval.toInt32(),
                                "function_name": functionName,
                                "function_offset": "{hex(offset)}"
                            }};
                            send(registerOutput);
                        }}
                    }});
                }} catch (err) {{
                    console.log("[ERROR] Error hooking function at address " + functionAddress + ": " + err.message);
                }}
            }}

            hookFunction(targetLibrary, targetFunctionOffset, "{name}");
        }}
        """
        hooks.append(hook)

    return "\n".join(hooks)