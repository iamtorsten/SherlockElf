import frida


class Inject:
    def __init__(self, target: str):
        """
        Die Klasse initialisieren und das Target (App) übergeben.
        """
        self.target = target

    def attach(self):
        """
        Das aktive USB Gerät auswählen und die Session erstellen.
        """
        device: frida.core.Device = frida.get_usb_device()
        app = device.get_frontmost_application()
        if app:
            target = app.pid
        else:
            target = self.target
        session: frida.core.Session = device.attach(target)

        return device, session

    def source(self, session, code):
        """
        Der Session aus der Funktion attach den JS Code zuweisen.
        """
        return session.create_script(code)