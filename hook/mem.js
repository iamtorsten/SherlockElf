const libName = "libmetasec_ov.so";
const delayBetweenDumps = 100; // Delay in milliseconds between each dump iteration

function sendMemoryChunk(base, chunkSize) {
    try {
        const buffer = Memory.readByteArray(ptr(base), chunkSize);
        send({
            base: base.toString(),
            chunkSize: chunkSize,
            data: buffer
        }, buffer);  // Send the buffer as the second argument
    } catch (e) {
        console.error("Error reading memory at " + base + ": " + e.message);
    }
}

function dumpLibraryMemory(libName) {
    const baseAddress = Module.findBaseAddress(libName);
    if (baseAddress === null) {
        console.log("Library not found: " + libName);
        return;
    }

    const libRange = Process.getRangeByAddress(baseAddress);
    console.log("Library base address: " + baseAddress);
    console.log("Library size: " + libRange.size);

    const chunkSize = 64 * 1024;  // Send 64 KB chunks
    for (let i = 0; i < libRange.size; i += chunkSize) {
        let size = Math.min(chunkSize, libRange.size - i);
        sendMemoryChunk(baseAddress.add(i), size);
    }
}

// Set an interval to continuously dump the library memory every `delayBetweenDumps` milliseconds
setInterval(() => {
    dumpLibraryMemory(libName);
}, delayBetweenDumps);
