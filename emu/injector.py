import frida


class Inject:
    def __init__(self, target: str):
        self.target = target

    def attach(self):
        # Attach to the target process
        device: frida.core.Device = frida.get_usb_device()
        app = device.get_frontmost_application()
        if app:
            target = app.pid
        else:
            target = self.target
        session: frida.core.Session = device.attach(target)

        return device, session
