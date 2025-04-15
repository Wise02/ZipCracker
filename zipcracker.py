import os
import sys
import time
import string
import itertools
import logging
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from multiprocessing import Pool, Manager
from typing import Iterator, Optional, Tuple

# Global variables for cancellation handling.
current_pool = None
brute_force_thread = None

# Attempt to import external libraries for ZIP and RAR support.
try:
    import pyzipper
    ZIP_SUPPORTED = True
except ImportError:
    ZIP_SUPPORTED = False

try:
    import rarfile
    RAR_SUPPORTED = True
except ImportError:
    RAR_SUPPORTED = False

# Set up logging to the console only.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def generate_passwords(min_length: int, max_length: int, hint: str, charset: str) -> Iterator[str]:
    """
    Generate every possible candidate password from the provided charset within the length range.
    If a hint is provided, yields only candidates that include the hint.
    """
    for length in range(min_length, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            candidate = ''.join(combo)
            if hint and hint not in candidate:
                continue
            yield candidate

def generate_passwords_from_wordlist(wordlist_file: str, hint: str) -> Iterator[str]:
    """
    Generate candidate passwords from a given wordlist file.
    Yields only candidates that contain the hint (if provided).
    """
    try:
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                candidate = line.strip()
                if candidate:
                    if hint and hint not in candidate:
                        continue
                    yield candidate
    except Exception as e:
        logging.error("Error reading wordlist: %s", e)

def get_encrypted_file_zip(zf) -> Optional[str]:
    """
    Return the first encrypted file in the ZIP archive.
    """
    for info in zf.infolist():
        if info.flag_bits & 0x1:
            return info.filename
    return None

def try_password(args: Tuple[str, str, str, 'Manager.Value', 'Manager.Value']) -> Tuple[Optional[str], bool]:
    """
    Try the candidate password on the archive.
    Returns (candidate, True) if successful; otherwise (candidate, False).
    """
    archive_path, archive_type, candidate, found_flag, found_password = args

    if found_flag.value:
        return (None, False)
    
    try:
        if archive_type == 'zip':
            if ZIP_SUPPORTED:
                with pyzipper.AESZipFile(archive_path, 'r') as zf:
                    enc_file = get_encrypted_file_zip(zf)
                    if enc_file is None:
                        raise Exception("No encrypted file found in archive.")
                    zf.read(enc_file, pwd=candidate.encode('utf-8'))
            else:
                import zipfile
                with zipfile.ZipFile(archive_path, 'r') as zf:
                    enc_file = None
                    for info in zf.infolist():
                        if info.flag_bits & 0x1:
                            enc_file = info.filename
                            break
                    if enc_file is None:
                        raise Exception("No encrypted file found in archive.")
                    zf.read(enc_file, pwd=candidate.encode('utf-8'))
        elif archive_type == 'rar' and RAR_SUPPORTED:
            with rarfile.RarFile(archive_path, 'r') as rf:
                test_file = rf.namelist()[0]
                rf.read(test_file, pwd=candidate)
        else:
            return (candidate, False)
        
        found_flag.value = True
        found_password.value = candidate
        return (candidate, True)
    except Exception:
        return (candidate, False)

def detect_archive_type(filepath: str) -> Optional[str]:
    """
    Determines the archive type based on its file extension.
    """
    ext = os.path.splitext(filepath)[1].lower()
    if ext == '.zip':
        return 'zip'
    elif ext == '.rar' and RAR_SUPPORTED:
        return 'rar'
    else:
        return None

def start_brute_force(archive_path: str, status_label: tk.Label, threads: int,
                      min_len: int, max_len: int, hint: str, wordlist: str, charset: str,
                      finish_callback) -> None:
    """
    Starts the brute force process using multiprocessing.
    Logs progress to the console and updates the GUI status.
    On success, extracts the files into a dedicated folder and displays a pop-up with details.
    The finish_callback is called at the end to unlock inputs.
    """
    global current_pool
    archive_type = detect_archive_type(archive_path)
    if archive_type is None:
        status_label.after(0, lambda: messagebox.showerror("Unsupported File",
                              "File must be a ZIP or RAR archive (with proper support installed)."))
        finish_callback()
        return

    with Manager() as manager:
        found_flag = manager.Value('b', False)
        found_password = manager.Value('s', "")

        pool = Pool(processes=threads)
        current_pool = pool  # Save reference for cancellation.
        total_attempts = 0
        start_time = time.time()

        # Use wordlist if provided and exists; else generate candidates using the given charset.
        if wordlist and os.path.exists(wordlist):
            candidate_generator = generate_passwords_from_wordlist(wordlist, hint)
        else:
            candidate_generator = generate_passwords(min_len, max_len, hint, charset)

        try:
            arg_generator = (
                (archive_path, archive_type, candidate, found_flag, found_password)
                for candidate in candidate_generator
            )
            for candidate, success in pool.imap(try_password, arg_generator, chunksize=1):
                if candidate is not None:
                    total_attempts += 1
                    logging.info("Attempt %d: %s", total_attempts, candidate)
                if total_attempts % 100 == 0 and total_attempts > 0:
                    # Schedule GUI update in main thread.
                    status_label.after(0, lambda t=total_attempts: status_label.config(text=f"Attempts: {t}"))
                if success:
                    pool.terminate()
                    break
        except KeyboardInterrupt:
            pool.terminate()
            logging.error("Brute force interrupted by user.")
            status_label.after(0, lambda: messagebox.showinfo("Interrupted", "Brute force was interrupted by the user."))
            finish_callback()
            return
        finally:
            pool.close()
            pool.join()
            current_pool = None

        elapsed = time.time() - start_time
        if found_flag.value:
            pwd = found_password.value
            msg = (f"SUCCESS! Password '{pwd}' found after {total_attempts} attempts "
                   f"in {elapsed:.2f} seconds.")
            logging.info(msg)
            # Create a dedicated extraction folder using the archive name.
            archive_name = os.path.splitext(os.path.basename(archive_path))[0]
            extract_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"extracted_{archive_name}")
            if not os.path.exists(extract_dir):
                os.makedirs(extract_dir)
            try:
                if archive_type == 'zip':
                    if ZIP_SUPPORTED:
                        with pyzipper.AESZipFile(archive_path, 'r') as zf:
                            zf.extractall(path=extract_dir, pwd=pwd.encode('utf-8'))
                    else:
                        import zipfile
                        with zipfile.ZipFile(archive_path, 'r') as zf:
                            zf.extractall(path=extract_dir, pwd=pwd.encode('utf-8'))
                elif archive_type == 'rar':
                    with rarfile.RarFile(archive_path, 'r') as rf:
                        rf.extractall(path=extract_dir, pwd=pwd)
                logging.info("Files extracted to: %s", extract_dir)
                status_label.after(0, lambda: messagebox.showinfo("Extraction Complete", 
                                      f"SUCCESS!\nPassword: {pwd}\nFiles have been extracted to:\n{extract_dir}"))
            except Exception as e:
                logging.error("Extraction error: %s", e)
                status_label.after(0, lambda: messagebox.showerror("Extraction Error", f"Could not extract files: {e}"))
        else:
            msg = (f"NO MATCH. Tried {total_attempts} passwords in {elapsed:.2f} seconds.")
            logging.info(msg)
            status_label.after(0, lambda: messagebox.showinfo("Not Found", msg))
        finish_callback()

def select_file(status_label: tk.Label, threads: int, min_len: int, max_len: int,
                hint: str, wordlist: str, charset: str, finish_callback) -> None:
    """
    Prompts the user to select an archive file and starts the brute force process.
    This is run in a separate thread so as not to block the GUI.
    """
    global brute_force_thread
    filepath = filedialog.askopenfilename(
        title="Select Archive File",
        filetypes=[("Archive files", "*.zip *.rar"), ("All files", "*.*")]
    )
    if filepath:
        status_label.config(text="Starting brute force...")
        logging.info("Starting brute force on: %s", filepath)
        brute_force_thread = threading.Thread(
            target=start_brute_force, 
            args=(filepath, status_label, threads, min_len, max_len, hint, wordlist, charset, finish_callback)
        )
        brute_force_thread.daemon = True
        brute_force_thread.start()

def build_gui() -> None:
    """
    Builds the Tkinter GUI for parameter input and launching the brute force attack.
    """
    root = tk.Tk()
    root.title("Archive Brute Forcer")
    root.geometry("550x500")
    root.resizable(False, False)

    dark_bg = "#2e2e2e"
    dark_fg = "#ffffff"
    entry_bg = "#3e3e3e"
    button_bg = "#4e4e4e"

    root.configure(bg=dark_bg)

    intro = tk.Label(root, text="Set CPU threads, password length range, optional hint, wordlist,\n"
                                "and character set options (if not using a wordlist).", 
                                wraplength=500, bg=dark_bg, fg=dark_fg)
    intro.pack(pady=10)

    # Parameters frame for threads, min/max lengths, and hint.
    params_frame = tk.Frame(root, bg=dark_bg)
    params_frame.pack(pady=5)

    tk.Label(params_frame, text="CPU Threads:", bg=dark_bg, fg=dark_fg).grid(row=0, column=0, sticky="w", padx=5, pady=2)
    threads_entry = tk.Entry(params_frame, width=5, bg=entry_bg, fg=dark_fg, insertbackground=dark_fg)
    threads_entry.insert(0, "6")
    threads_entry.grid(row=0, column=1, pady=2)

    tk.Label(params_frame, text="Min Length:", bg=dark_bg, fg=dark_fg).grid(row=1, column=0, sticky="w", padx=5, pady=2)
    min_entry = tk.Entry(params_frame, width=5, bg=entry_bg, fg=dark_fg, insertbackground=dark_fg)
    min_entry.insert(0, "1")
    min_entry.grid(row=1, column=1, pady=2)

    tk.Label(params_frame, text="Max Length:", bg=dark_bg, fg=dark_fg).grid(row=2, column=0, sticky="w", padx=5, pady=2)
    max_entry = tk.Entry(params_frame, width=5, bg=entry_bg, fg=dark_fg, insertbackground=dark_fg)
    max_entry.insert(0, "10")
    max_entry.grid(row=2, column=1, pady=2)

    tk.Label(params_frame, text="Hint (optional):", bg=dark_bg, fg=dark_fg).grid(row=3, column=0, sticky="w", padx=5, pady=2)
    hint_entry = tk.Entry(params_frame, width=20, bg=entry_bg, fg=dark_fg, insertbackground=dark_fg)
    hint_entry.grid(row=3, column=1, pady=2)

    # Wordlist frame.
    wordlist_frame = tk.Frame(root, bg=dark_bg)
    wordlist_frame.pack(pady=2)
    tk.Label(wordlist_frame, text="Wordlist (optional):", bg=dark_bg, fg=dark_fg).pack(side=tk.LEFT, padx=5)
    wordlist_entry = tk.Entry(wordlist_frame, width=30, bg=entry_bg, fg=dark_fg, insertbackground=dark_fg)
    wordlist_entry.pack(side=tk.LEFT, padx=5)

    def browse_wordlist() -> None:
        file_path = filedialog.askopenfilename(
            title="Select Wordlist File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            wordlist_entry.delete(0, tk.END)
            wordlist_entry.insert(0, file_path)

    browse_btn = tk.Button(wordlist_frame, text="Browse", command=browse_wordlist, bg=button_bg, fg=dark_fg)
    browse_btn.pack(side=tk.LEFT, padx=5)

    # Character set options.
    charset_frame = tk.LabelFrame(root, text="Character Set Options", bg=dark_bg, fg=dark_fg, padx=3, pady=2)
    charset_frame.pack(pady=10, padx=10, fill="x")
    
    # Create checkbuttons and store their references.
    lower_var = tk.BooleanVar(value=True)
    upper_var = tk.BooleanVar(value=False)
    digits_var = tk.BooleanVar(value=True)
    special_var = tk.BooleanVar(value=False)

    # Note: Added "selectcolor" and "disabledforeground" so selections stay visible.
    lower_check = tk.Checkbutton(charset_frame, text="Lowercase (a-z)", variable=lower_var,
                   command=lambda: print("Lowercase toggled:", lower_var.get()),
                   bg=dark_bg, fg=dark_fg, selectcolor="#5e5e5e", disabledforeground=dark_fg)
    lower_check.grid(row=0, column=0, sticky="w", padx=5, pady=2)
    
    upper_check = tk.Checkbutton(charset_frame, text="Uppercase (A-Z)", variable=upper_var,
                   command=lambda: print("Uppercase toggled:", upper_var.get()),
                   bg=dark_bg, fg=dark_fg, selectcolor="#5e5e5e", disabledforeground=dark_fg)
    upper_check.grid(row=1, column=0, sticky="w", padx=5, pady=2)
    
    digits_check = tk.Checkbutton(charset_frame, text="Numbers (0-9)", variable=digits_var,
                   command=lambda: print("Numbers toggled:", digits_var.get()),
                   bg=dark_bg, fg=dark_fg, selectcolor="#5e5e5e", disabledforeground=dark_fg)
    digits_check.grid(row=0, column=1, sticky="w", padx=5, pady=2)
    
    special_check = tk.Checkbutton(charset_frame, text="Special (!@#$...) ", variable=special_var,
                   command=lambda: print("Special toggled:", special_var.get()),
                   bg=dark_bg, fg=dark_fg, selectcolor="#5e5e5e", disabledforeground=dark_fg)
    special_check.grid(row=1, column=1, sticky="w", padx=5, pady=2)

    status_label = tk.Label(root, text="Idle", fg=dark_fg, bg=dark_bg)
    status_label.pack(pady=10)

    # List of all input widgets that should be locked during cracking.
    input_widgets = [threads_entry, min_entry, max_entry, hint_entry, wordlist_entry,
                     lower_check, upper_check, digits_check, special_check]

    # Define helper functions to lock and unlock inputs.
    def lock_inputs():
        for widget in input_widgets:
            widget.configure(state="disabled")
        start_btn.configure(state="disabled")
        cancel_btn.configure(state="normal")  # Enable the Cancel button.

    def unlock_inputs():
        for widget in input_widgets:
            widget.configure(state="normal")
        start_btn.configure(state="normal")
        cancel_btn.configure(state="disabled")  # Disable the Cancel button.

    # Function to be called when the brute force process finishes (or is cancelled).
    def finish_callback():
        status_label.after(0, unlock_inputs)

    # Cancel function – terminates the running pool.
    def cancel_brute_force():
        global current_pool
        if current_pool is not None:
            current_pool.terminate()
        messagebox.showinfo("Cancelled", "Brute force operation has been cancelled.")
        finish_callback()

    # Start button callback.
    def setup_and_run() -> None:
        try:
            threads_val = int(threads_entry.get())
            min_val = int(min_entry.get())
            max_val = int(max_entry.get())
            if min_val > max_val:
                raise ValueError("Min length cannot be greater than max length.")
        except ValueError as ve:
            messagebox.showerror("Input Error", f"Invalid numeric input: {ve}")
            return

        hint = hint_entry.get().strip()
        wordlist = wordlist_entry.get().strip()

        # Build the charset based on selected options.
        charset = ""
        if lower_var.get():
            charset += string.ascii_lowercase
        if upper_var.get():
            charset += string.ascii_uppercase
        if digits_var.get():
            charset += string.digits
        if special_var.get():
            charset += string.punctuation

        if not charset and (not wordlist or not os.path.exists(wordlist)):
            messagebox.showerror("Input Error", "No character set selected! Please enable at least one option.")
            return

        lock_inputs()
        # Start the file selection and brute force process.
        select_file(status_label, threads_val, min_val, max_val, hint, wordlist, charset, finish_callback)

    # Start and Cancel buttons.
    start_btn = tk.Button(root, text="Start Brute Force", command=setup_and_run, bg=button_bg, fg=dark_fg)
    start_btn.pack(pady=10)

    cancel_btn = tk.Button(root, text="Cancel", command=cancel_brute_force, bg=button_bg, fg=dark_fg, state="disabled")
    cancel_btn.pack(pady=5)

    note = tk.Label(root, text="made by Itay & BlackPaw", 
                     fg="#ffffff", bg=dark_bg, font=("Arial", 10))
    note.pack(side="bottom", pady=10)

    root.mainloop()

if __name__ == '__main__':
    from multiprocessing import freeze_support
    freeze_support()
    build_gui()
