import os

import tkinter              as tk
from tkinter                import filedialog, messagebox, simpledialog
import tkinter.scrolledtext as scrolledtext

class CodeEditor:
    def __init__(self, root):
        self.root = root
        self.filename = None

        # Erstelle das Editor-Fenster
        self.editor_window = tk.Toplevel(root)
        self.editor_window.title("Code Editor")
        self.editor_window.geometry("800x600")

        # Erstelle das Textfeld mit Scrollbalken und Tabs auf 0,5 cm
        self.text_area = scrolledtext.ScrolledText(self.editor_window, wrap=tk.WORD, undo=True, tabs=("0.5c"))
        self.text_area.pack(fill=tk.BOTH, expand=True)

        # Erstelle das Menü
        self.menu = tk.Menu(self.editor_window)
        self.editor_window.config(menu=self.menu)

        # Datei-Menü
        file_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open", command=self.open_file)
        file_menu.add_command(label="Save", command=self.save_file)
        file_menu.add_command(label="Save As", command=self.save_file_as)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.editor_window.destroy)

        # Bearbeiten-Menü
        edit_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Edit", menu=edit_menu)
        edit_menu.add_command(label="Undo", command=self.text_area.edit_undo)
        edit_menu.add_command(label="Redo", command=self.text_area.edit_redo)
        edit_menu.add_separator()
        edit_menu.add_command(label="Find", command=self.find_text)
        edit_menu.add_command(label="Replace", command=self.replace_text)

    def open_file(self):
        self.filename = filedialog.askopenfilename(
            defaultextension=".txt",
            filetypes=[("Python Files", "*.py"), ("JavaScript Files", "*.js"), ("All Files", "*.*")]
        )
        if self.filename:
            with open(self.filename, "r") as file:
                content = file.read()
            self.text_area.delete(1.0, tk.END)
            self.text_area.insert(tk.INSERT, content)
            self.editor_window.title(f"Code Editor - {os.path.normpath(self.filename)}")

    def save_file(self):
        if self.filename:
            with open(self.filename, "w") as file:
                file.write(self.text_area.get(1.0, tk.END))
        else:
            self.save_file_as()

    def save_file_as(self):
        self.filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Python Files", "*.py"), ("JavaScript Files", "*.js"), ("All Files", "*.*")]
        )
        if self.filename:
            with open(self.filename, "w") as file:
                file.write(self.text_area.get(1.0, tk.END))
            self.editor_window.title(f"Code Editor - {os.path.normpath(self.filename)}")

    def find_text(self):
        search_term = simpledialog.askstring("Find", "Enter text to find:")
        if search_term:
            start_pos = "1.0"
            while True:
                start_pos = self.text_area.search(search_term, start_pos, stopindex=tk.END)
                if not start_pos:
                    break
                end_pos = f"{start_pos}+{len(search_term)}c"
                self.text_area.tag_add("highlight", start_pos, end_pos)
                self.text_area.tag_config("highlight", background="yellow", foreground="black")
                start_pos = end_pos

    def replace_text(self):
        search_term = simpledialog.askstring("Find", "Enter text to replace:")
        replace_term = simpledialog.askstring("Replace", "Enter replacement text:")
        if search_term and replace_term:
            content = self.text_area.get(1.0, tk.END)
            new_content = content.replace(search_term, replace_term)
            self.text_area.delete(1.0, tk.END)
            self.text_area.insert(1.0, new_content)