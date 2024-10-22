# Plugin: Hook libso
# Description: Hook libso

from emu.injector import Inject

target = "" # Enter the name of the app to be monitored here.

js_code = """
rpc.exports = {
    findModule: function (name) {
        const libso = Process.findModuleByName(name);
        return libso !== null;
    },
    dumpSo: function (name) {
        const libso = Process.findModuleByName(name);
        if (libso === null) {
            console.log("find moduel failed");
            return '';
        }
        Memory.protect(ptr(libso.base), libso.size, 'rwx');
        const libso_buffer = ptr(libso.base).readByteArray(libso.size);
        return libso_buffer;
    },
}
"""


def main():
    # Setup Device, Session and Source
    sherlock = Inject(target=target)
    device, session = sherlock.attach()
    script = sherlock.source(session, js_code)

    script.load()

    # ... do more stuff


if __name__ == '__main__':
    main()