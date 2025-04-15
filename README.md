# ZipCracker 🔐💥

**ZipCracker** is a Python-based GUI tool designed to perform brute-force password recovery on ZIP and RAR archives. This tool offers configurable character sets, wordlist support, and multi-threaded cracking with an intuitive Tkinter interface. It even lets you cancel long operations on the fly! ⚡️🚀

## Features ✨

- **User-Friendly GUI:** Enjoy a sleek, Tkinter-based interface.
- **Customizable Character Sets:** Choose lowercase, uppercase, numbers, and special characters when not using a wordlist.
- **Wordlist Support:** Use your own wordlists to attempt passwords.
- **Multi-processing:** Leverage multiple CPU cores to speed up brute-force attempts.
- **Automatic Extraction:** Upon success, the archive is extracted into a dedicated folder.
- **Cross-Platform:** Runs on Windows, macOS, and Linux (with the appropriate Python dependencies).

## Requirements 📦

- **Python 3.6+**
- [pyzipper](https://pypi.org/project/pyzipper/) (for encrypted ZIP archives)
- [rarfile](https://pypi.org/project/rarfile/) (for RAR archives)  
  > **Note:** On some systems, `rarfile` may require [UnRAR](https://www.rarlab.com/rar_add.htm) installed and available in your system's PATH.

Install the required packages using:

```bash
pip install pyzipper rarfile
```

## Installation 🛠

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/Wise02/ZipCracker.git
   ```

2. **Navigate to the Project Directory:**

   ```bash
   cd ZipCracker
   ```

3. **(Optional) Create a Virtual Environment:**

   ```bash
   python -m venv venv
   source venv\Scripts\activate
   ```

4. **Install Dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

## Usage 🎯

1. **Start the Application:**
   On Linux:
   Run the Python script:
   
   ```bash
   python zipcracker.py
   ```

   On Windows: double-click the batch file **launcher.bat**.

2. **Configure the Settings:**

   - **Threads:** Set the desired number of CPU threads.
   - **Password Length:** Input the minimum and maximum lengths for brute forcing.
   - **Hint (Optional):** Provide a hint to narrow down guesses.
   - **Wordlist (Optional):** Browse to use a wordlist file.
   - **Character Sets:** Check the boxes for lowercase, uppercase, numbers, and/or special characters if you are not using a wordlist.

3. **Start Cracking:**

   Click **Start Brute Force** and watch the progress on the console and GUI. If needed, hit **Cancel** to stop the process immediately.  
   When successful, a pop-up will display the recovered password and the extraction folder.

## Contributing 🤝

Contributions are welcome! Feel free to fork the repository and submit pull requests for improvements, bug fixes, or new features.

## License 📄

This project is licensed under the [MIT License](LICENSE).

## Disclaimer ⚠️

**Archive Brute Forcer** is intended for educational purposes only. Use this tool **ONLY** on archives for which you have explicit permission to perform password recovery. The author is not responsible for any misuse of this tool.

---

Happy Cracking! 🔓💻
