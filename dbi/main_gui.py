import  tkinter                 as tk
from    tkinter                 import filedialog
from    dbi.disassembler_gui    import DisassemblerGUI


class StartGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Select Platform")
        self.platform_var = tk.StringVar(value="Android")

        self.create_widgets()

    def create_widgets(self):
        frame = tk.Frame(self.root, padx=20, pady=20)
        frame.pack()

        label = tk.Label(frame, text="Select the Platform")
        label.pack(anchor="w")

        android_radio = tk.Radiobutton(frame, text="Android ARM64", variable=self.platform_var, value="Android")
        android_radio.pack(anchor="w")

        ios_radio = tk.Radiobutton(frame, text="iOS ARM64", variable=self.platform_var, value="iOS")
        ios_radio.pack(anchor="w")

        button_frame = tk.Frame(frame)
        button_frame.pack(pady=10)

        open_button = tk.Button(button_frame, text="Open File", command=self.open_file)
        open_button.pack(side="left", padx=5)

        exit_button = tk.Button(button_frame, text="Exit", command=self.root.quit)
        exit_button.pack(side="left", padx=5)

    def open_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("All files", "*.*"), ("ELF files", "*.so"), ("Mach-O files", "*.dylib")]
        )
        if file_path:
            self.root.withdraw()  # Hide the current window
            platform = self.platform_var.get()
            disassembler = platform  # "Android" or "iOS"
            DisassemblerGUI(tk.Toplevel(self.root), disassembler, file_path)