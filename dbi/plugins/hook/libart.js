var exports = Module.enumerateExportsSync("libart.so");
exports.forEach(function(exp) {
    console.log(exp.name);
});