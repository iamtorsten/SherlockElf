from colorama import Fore

def Print(text: str):
    print(
        f"{Fore.MAGENTA}{text}{Fore.RESET}")

def Print_c_Code(text: str):
    print(
        f"{Fore.YELLOW}{text}{Fore.RESET}")

def Print_py_Code(text: str):
    print(
        f"{Fore.LIGHTCYAN_EX}{text}{Fore.RESET}")