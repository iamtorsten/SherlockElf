# Android and iOS DBI framework for dynamic analysis of ELF and Macho-O binaries

import  tkinter         as tk
from    dbi.main_gui    import StartGUI

if __name__ == "__main__":
    root = tk.Tk()
    gui = StartGUI(root)

    root.mainloop()
