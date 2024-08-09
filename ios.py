from emu.injector import Inject

target = "" # Enter the name of the app to be monitored here.

with open("hook/stalker.js") as f:
    js_code = f.read()

def main():
    device, session = Inject(target=target).attach()
    script = session.create_script(js_code)
    script.load()

    # ... do more stuff


if __name__ == '__main__':
    main()