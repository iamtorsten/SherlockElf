import os

class PluginManager:
    def __init__(self, plugins_dir="plugins"):
        self.plugins_dir = plugins_dir
        self.plugins = {}

        self.load_plugins()

    def load_plugins(self):
        """
        Lädt alle Plugins aus dem Plugins-Verzeichnis und speichert sie im Dictionary.
        """
        if not os.path.exists(self.plugins_dir):
            os.makedirs(self.plugins_dir)

        for filename in os.listdir(self.plugins_dir):
            if filename.endswith(".py"):
                filepath = os.path.join(self.plugins_dir, filename)
                with open(filepath, 'r') as file:
                    first_line = file.readline().strip()
                    if first_line.startswith("# Plugin:"):
                        plugin_name = first_line.split(":")[1].strip()
                        self.plugins[plugin_name] = filepath

    def get_plugins(self):
        """
        Gibt eine Liste der verfügbaren Plugins zurück.
        """
        return list(self.plugins.keys())

    def get_plugin_path(self, plugin_name):
        """
        Gibt den Pfad zu einem Plugin anhand seines Namens zurück.
        """
        return self.plugins.get(plugin_name, None)
