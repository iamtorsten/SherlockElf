function waitForLibraryAndHook(libraryName) {
    var lib = Process.findModuleByName(libraryName);
    if (lib) {
        hookB64Functions(lib);
    } else {
        setTimeout(function() { waitForLibraryAndHook(libraryName); }, 100);
    }
}

function hookB64Functions(lib) {
    var exports = Module.enumerateExportsSync(lib.name);

    var b64Decode = null;
    var b64Encode = null;

    for (var i = 0; i < exports.length; i++) {
        if (exports[i].name === "b64_decode") {
            b64Decode = exports[i].address;
        } else if (exports[i].name === "b64_encode") {
            b64Encode = exports[i].address;
        }
    }

    if (b64Decode) {
        Interceptor.attach(b64Decode, {
            onEnter: function(args) {
                var input = args[0].readCString();
                var length = args[1].toInt32();
                send({ function: 'b64_decode', input: input, length: length });
            },
            onLeave: function(retval) {
                send({ function: 'b64_decode_return', retval: retval.readCString() });
            }
        });
        send({ success: "Hooked b64_decode" });
    } else {
        send({ error: "b64_decode not found" });
    }

    if (b64Encode) {
        Interceptor.attach(b64Encode, {
            onEnter: function(args) {
                var input = args[0].readCString();
                var length = args[1].toInt32();
                send({ function: 'b64_encode', input: input, length: length });
            },
            onLeave: function(retval) {
                send({ function: 'b64_encode_return', retval: retval.readCString() });
            }
        });
        send({ success: "Hooked b64_encode" });
    } else {
        send({ error: "b64_encode not found" });
    }
}

// Start waiting for the library to be loaded and then hook functions
waitForLibraryAndHook("libb64.so");