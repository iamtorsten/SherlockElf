try {
    // Hook the strlen function
    Interceptor.attach(Module.findExportByName("libc.so", "strlen"), {
        onEnter: function(args) {
            this.str = Memory.readUtf8String(args[0]);
            send("strlen called with argument: " + this.str);
        },
        onLeave: function(retval) {
            send("strlen returned: " + retval.toInt32());
        }
    });
    send("Frida script loaded successfully");
} catch (error) {
    send("Error: " + error.message);
}