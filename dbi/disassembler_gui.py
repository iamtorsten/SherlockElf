import multiprocessing
import sys
import time
import tkinter as tk
import webbrowser
import threading
import queue

from tkinter                    import Text, Scrollbar, RIGHT, Y, X, BOTTOM, LEFT, VERTICAL, HORIZONTAL, messagebox, Menu, simpledialog
from dbi.android_disassembler   import AndroidDisassembler
from dbi.code_editor            import CodeEditor
from dbi.ios_disassembler       import IOSDisassembler
from dbi.executor               import Executor
from dbi.output_redirector      import OutputRedirector
from dbi.plugin_manager         import PluginManager


def execute_code_in_process(code, queue, stop_event):
    try:
        # Umleitung der Standardausgabe und Standardfehlerausgabe
        sys.stdout = OutputRedirector(queue)
        sys.stderr = OutputRedirector(queue)

        # Dauerschleife, die regelmäßig die Ausführung fortsetzt
        exec(code, {"__name__": "__main__"})

        while not stop_event.is_set():
            time.sleep(0.1)  # Warten, um CPU-Last zu reduzieren

    except Exception as e:
        queue.put(f"Exception: {str(e)}\n")
    finally:
        queue.put("Execution finished.\n")
        sys.stdout = sys.__stdout__  # stdout zurücksetzen
        sys.stderr = sys.__stderr__  # stderr zurücksetzen

class DisassemblerGUI:
    def __init__(self, root, disassembler_type, file_path):
        self.root = root
        self.root.title("SherlockElf DBI ARM64")
        self.root.state('zoomed')
        self.root.configure(bg='#ffffff')

        self.execution_thread = None

        self.disassembler_type = disassembler_type

        self.stop_flag = threading.Event()

        self.process = None
        self.queue = multiprocessing.Queue()
        self.stop_event = multiprocessing.Event()

        # PluginManager initialisieren
        self.plugin_manager = PluginManager()

        # Hauptbereich mit PanedWindow für veränderbare Größen
        self.main_paned_window = tk.PanedWindow(self.root, orient=tk.VERTICAL, bg='#ffffff')
        self.main_paned_window.pack(fill=tk.BOTH, expand=True)

        # Menüleiste
        self.menubar = tk.Menu(self.root)
        self.root.config(menu=self.menubar)

        # File-Menü erstellen
        self.file_menu = Menu(self.menubar, tearoff=0, bg='#ffffff', fg='black')
        self.file_menu.add_command(label="Quit", command=self.root.quit)
        self.menubar.add_cascade(label="File", menu=self.file_menu)

        # Edit-Menü erstellen
        self.edit_menu = Menu(self.menubar, tearoff=0, bg='#ffffff', fg='black')
        self.edit_menu.add_command(label="Search Disassembly", command=self.search_disassembly)
        self.edit_menu.add_command(label="Back", command=self.undo_disassembly_change)
        self.menubar.add_cascade(label="Edit", menu=self.edit_menu)

        # Plugin-Menü erstellen
        self.plugins_menu = Menu(self.menubar, tearoff=0, bg='#ffffff', fg='black')
        self.menubar.add_cascade(label="Plugins", menu=self.plugins_menu)
        self.load_plugins_into_menu()  # Plugins in das Menü laden

        # Code-Editor Menü erstellen
        editor_menu = Menu(self.menubar, tearoff=0, bg='#ffffff', fg='black')
        self.menubar.add_cascade(label="Code Editor", menu=editor_menu)
        editor_menu.add_command(label="Open Code Editor", command=self.open_code_editor)

        # Help-Menü erstellen
        self.help_menu = Menu(self.menubar, tearoff=0, bg='#ffffff', fg='black')
        self.help_menu.add_command(label="About", command=self.show_about_info)
        self.help_menu.add_command(label="Telegram", command=self.open_telegram_link)
        self.menubar.add_cascade(label="Help", menu=self.help_menu)

        # Bereich für die drei Hauptspalten
        self.paned_window = tk.PanedWindow(self.main_paned_window, orient=tk.HORIZONTAL, bg='#ffffff')
        self.main_paned_window.add(self.paned_window)

        # Untere Leiste: Terminalausgabe (jetzt sicher am unteren Rand)
        self.bottom_frame = tk.LabelFrame(self.root, text="Terminal", height=100, bg='#ffffff', fg='black')
        self.terminal_output = Text(self.bottom_frame, height=10, wrap="none", bg="white", fg="black",
                                    insertbackground="black", state=tk.DISABLED)
        self.terminal_scrollbar_y = Scrollbar(self.bottom_frame, orient=VERTICAL)
        self.terminal_scrollbar_x = Scrollbar(self.bottom_frame, orient=HORIZONTAL)
        self.terminal_scrollbar_y.pack(side=RIGHT, fill=Y)
        self.terminal_scrollbar_x.pack(side=BOTTOM, fill=X)
        self.terminal_output.pack(fill=tk.BOTH, expand=True)
        self.terminal_output.config(yscrollcommand=self.terminal_scrollbar_y.set,
                                    xscrollcommand=self.terminal_scrollbar_x.set)
        self.terminal_scrollbar_y.config(command=self.terminal_output.yview)
        self.terminal_scrollbar_x.config(command=self.terminal_output.xview)
        self.main_paned_window.add(self.bottom_frame)

        # Linke Spalte: Liste der Funktionen mit Scrollbar
        self.left_frame = tk.LabelFrame(self.paned_window, text="Functions", width=200, bg='#ffffff', fg='black')
        self.function_list = tk.Listbox(self.left_frame, fg="black", bg="white", selectbackground="blue",
                                        selectforeground="white")
        self.function_scrollbar = Scrollbar(self.left_frame)
        self.function_scrollbar.pack(side=RIGHT, fill=Y)
        self.function_list.pack(fill=tk.BOTH, expand=True)
        self.function_list.config(yscrollcommand=self.function_scrollbar.set)
        self.function_scrollbar.config(command=self.function_list.yview)
        self.function_list.bind("<<ListboxSelect>>", self.on_function_select)
        self.paned_window.add(self.left_frame)

        # Mittlere Spalte: Disassemblierter Code mit Scrollbar, weißes Design
        self.middle_frame = tk.LabelFrame(self.paned_window, text="Disassembly", width=400, bg='#ffffff', fg='black')
        self.disassembly_area = Text(self.middle_frame, wrap="none", bg="white", fg="black", insertbackground="black")
        self.disassembly_scrollbar_y = Scrollbar(self.middle_frame, orient=VERTICAL)
        self.disassembly_scrollbar_x = Scrollbar(self.middle_frame, orient=HORIZONTAL)
        self.disassembly_scrollbar_y.pack(side=RIGHT, fill=Y)
        self.disassembly_scrollbar_x.pack(side=BOTTOM, fill=X)
        self.disassembly_area.pack(fill=tk.BOTH, expand=True)
        self.disassembly_area.config(yscrollcommand=self.disassembly_scrollbar_y.set,
                                     xscrollcommand=self.disassembly_scrollbar_x.set)
        self.disassembly_scrollbar_y.config(command=self.disassembly_area.yview)
        self.disassembly_scrollbar_x.config(command=self.disassembly_area.xview)
        self.disassembly_area.bind("<Button-3>", self.show_popup_menu)
        self.disassembly_area.bind("<B1-Motion>", self.update_selection)
        self.paned_window.add(self.middle_frame)

        # Rechte Spalte: Python-Editor mit Run/Stop-Buttons, Scrollbar, und Filename Label
        self.right_frame = tk.LabelFrame(self.paned_window, text="Python Editor", width=400, bg='#ffffff', fg='black')
        self.python_editor = Text(self.right_frame, bg="white", fg="black", insertbackground="black", wrap="none", tabs=("0.5c"))
        self.python_scrollbar_y = Scrollbar(self.right_frame, orient=VERTICAL)
        self.python_scrollbar_x = Scrollbar(self.right_frame, orient=HORIZONTAL)
        self.python_scrollbar_y.pack(side=RIGHT, fill=Y)
        self.python_scrollbar_x.pack(side=BOTTOM, fill=X)
        self.python_editor.pack(fill=tk.BOTH, expand=True)
        self.python_editor.config(yscrollcommand=self.python_scrollbar_y.set,
                                  xscrollcommand=self.python_scrollbar_x.set)
        self.python_scrollbar_y.config(command=self.python_editor.yview)
        self.python_scrollbar_x.config(command=self.python_editor.xview)

        # Filename Label hinzufügen
        self.filename_label = tk.Label(self.right_frame, text="", bg='#ffffff', fg='black')
        self.filename_label.pack(side=LEFT, padx=5, pady=5)

        # Run and Stop Buttons
        self.run_button = tk.Button(self.right_frame, text="Run", command=self.run_python_code, bg='#ffffff',
                                    fg='black')
        self.run_button.pack(side=LEFT, padx=5, pady=5)
        self.stop_button = tk.Button(self.right_frame, text="Stop", command=self.stop_python_code, bg='#ffffff',
                                     fg='black')
        self.stop_button.pack(side=LEFT, padx=5, pady=5)

        self.paned_window.add(self.right_frame)

        # Initialize Executor and Disassembler
        self.function_positions = {}  # Initialize the function_positions dictionary
        self.executor = Executor(self.terminal_output)

        if self.disassembler_type == "Android":
            self.disassembler = AndroidDisassembler(self.disassembly_area, self.function_list, self.function_positions)
        else:
            self.disassembler = IOSDisassembler(self.disassembly_area, self.function_list, self.function_positions)

        # Start processing the file
        self.disassembler.process_file(file_path)

        # Popup-Menü erstellen
        self.popup_menu = tk.Menu(self.root, tearoff=0, bg='#ffffff', fg='black')
        self.popup_menu.add_command(label="Copy", command=self.copy_to_clipboard)

        # Initiale Markierungen und Zustand für Undo
        self.undo_stack = []
        self.last_search_position = "1.0"  # Position, wo die letzte Suche endete

    def open_code_editor(self):
        CodeEditor(self.root)

    def load_plugins_into_menu(self):
        """
        Lädt die erkannten Plugins in das Plugin-Menü.
        """
        plugins = self.plugin_manager.get_plugins()
        for plugin_name in plugins:
            self.plugins_menu.add_command(label=plugin_name, command=lambda name=plugin_name: self.load_plugin(name))

    def load_plugin(self, plugin_name):
        """
        Lädt das ausgewählte Plugin in den Python-Editor.
        """
        plugin_path = self.plugin_manager.get_plugin_path(plugin_name)
        if plugin_path:
            with open(plugin_path, 'r') as file:
                content = file.read()
                self.python_editor.delete(1.0, tk.END)
                self.python_editor.insert(tk.END, content)
                self.filename_label.config(text=f"Loaded: {plugin_name}")

    def on_function_select(self, event):
        widget = event.widget
        selection = widget.curselection()
        if selection:
            index = selection[0]
            function_name = widget.get(index)
            pos = self.function_positions.get(function_name, None)
            if pos:
                self.disassembly_area.see(pos)
                self.disassembly_area.tag_remove("sel", "1.0", "end")
                self.disassembly_area.tag_add("sel", pos, f"{pos} lineend")

    def show_popup_menu(self, event):
        try:
            self.popup_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.popup_menu.grab_release()

    def copy_to_clipboard(self):
        selection = self.disassembly_area.get("sel.first", "sel.last")
        self.root.clipboard_clear()
        self.root.clipboard_append(selection)

    def update_selection(self, event):
        try:
            # Änderungen zur Undo-Stack hinzufügen
            self.undo_stack.append(self.disassembly_area.get("1.0", tk.END))
            # Entfernen aller alten Markierungen
            self.disassembly_area.tag_remove("sel", "1.0", "end")

            # Neuen Bereich markieren
            self.disassembly_area.tag_add("sel", "sel.first", "sel.last")

            # Priorität der Markierung erhöhen
            self.disassembly_area.tag_raise("sel")

            # Stellen Sie sicher, dass der markierte Bereich hervorgehoben wird
            self.disassembly_area.tag_configure("sel", background="blue", foreground="white")

        except tk.TclError:
            pass  # Fehler verhindern, wenn keine Auswahl gemacht wurde

    def run_python_code(self):
        if self.process is not None and self.process.is_alive():
            return  # Keine neue Ausführung starten, wenn bereits eine läuft

        code = self.python_editor.get("1.0", tk.END)
        self.queue = multiprocessing.Queue()  # Queue zurücksetzen
        self.stop_event.clear()

        # Starten der Ausführung in einem neuen Prozess
        self.process = multiprocessing.Process(target=execute_code_in_process, args=(code, self.queue, self.stop_event))
        self.process.start()

        self.root.after(100, self.check_queue)  # Überprüfung der Queue starten

    def stop_python_code(self):
        if self.process is not None and self.process.is_alive():
            self.stop_event.set()  # Stop-Signal setzen
            self.process.join(timeout=2)  # Warten, bis der Prozess beendet wird
            self.process = None  # Prozess zurücksetzen

    def check_queue(self):
        while not self.queue.empty():
            try:
                message = self.queue.get_nowait()
                # Entfernen von unnötigen Leerzeilen am Ende der Nachricht
                if message.strip():
                    self.terminal_output.configure(state=tk.NORMAL)
                    self.terminal_output.insert(tk.END, message.strip() + "\n")
                    self.terminal_output.configure(state=tk.DISABLED)
                    self.terminal_output.see(tk.END)
            except queue.Empty:
                break

        if self.process is not None and self.process.is_alive():
            self.root.after(100, self.check_queue)  # Fortsetzen der Queue-Überprüfung

    def search_disassembly(self):
        search_term = simpledialog.askstring("Search Disassembly", "Enter text to search:")
        if search_term:
            start_pos = self.disassembly_area.search(search_term, self.last_search_position, stopindex=tk.END)
            if start_pos:
                end_pos = f"{start_pos}+{len(search_term)}c"
                self.disassembly_area.tag_remove('highlight', '1.0', tk.END)  # Entfernt vorherige Markierungen
                self.disassembly_area.tag_add("highlight", start_pos, end_pos)
                self.disassembly_area.tag_config("highlight", background="yellow", foreground="black")
                self.disassembly_area.mark_set("insert", end_pos)  # Bewegt den Cursor ans Ende der Markierung
                self.disassembly_area.see(start_pos)  # Scrollt zur gefundenen Stelle
                self.last_search_position = end_pos  # Setzt den neuen Startpunkt für die nächste Suche
            else:
                messagebox.showinfo("Search", "No more occurrences found.")
                self.last_search_position = "1.0"  # Setzt die Suche zurück

    def undo_disassembly_change(self):
        if self.undo_stack:
            previous_state = self.undo_stack.pop()
            self.disassembly_area.delete("1.0", tk.END)
            self.disassembly_area.insert(tk.END, previous_state)
        else:
            messagebox.showinfo("Undo", "Nothing to undo")

    def show_about_info(self):
        messagebox.showinfo("About", "SherlockElf DBI ARM64\nVersion 1.0\nAuthor: Torsten Klement")

    def open_telegram_link(self):
        webbrowser.open("https://t.me/iamtorsten")
