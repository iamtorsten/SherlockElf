import os
import subprocess
import shutil
import sys

from tkinter import Text, messagebox



class Executor:
    def __init__(self, terminal_output: Text):
        self.terminal_output = terminal_output
        self.process = None

    def find_python(self):
        # Versuche zuerst, den Python-Interpreter über sys.executable zu finden
        python_executable = sys.executable

        if python_executable and os.path.exists(python_executable):
            return python_executable

        # Fallback auf shutil.which() oder umgebungsvariablen PATH
        python_executable = shutil.which("python3") or shutil.which("python")

        # Wenn nichts gefunden wurde
        if not python_executable:
            messagebox.showerror("Python nicht gefunden",
                                 "Python konnte nicht gefunden werden. "
                                 "Bitte installieren Sie Python und stellen Sie sicher, dass es in den Umgebungsvariablen (`PATH`) enthalten ist.")
            return None

        return python_executable

    def run_python_code(self, code):
        self.terminal_output.config(state="normal")
        self.terminal_output.delete("1.0", "end")

        python_executable = self.find_python()

        if not python_executable:
            return  # Wenn kein Python gefunden wurde, abbrechen

        try:
            self.process = subprocess.Popen(
                [python_executable, "-c", code],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            stdout, stderr = self.process.communicate()

            # Verwenden von 'replace', um nicht-dekodierbare Zeichen zu ersetzen
            self.terminal_output.insert("end", stdout.decode("utf-8", errors="replace"))
            self.terminal_output.insert("end", stderr.decode("utf-8", errors="replace"))

        except Exception as e:
            messagebox.showerror("Error", str(e))
        finally:
            self.terminal_output.config(state="disabled")

    def stop_python_code(self):
        if self.process:
            self.process.terminate()
            self.process = None
