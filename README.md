# 🛡️ VM Security Tool

**VM Security Tool** is a lightweight Python-based utility designed to perform basic security assessments on virtual machines. It helps identify potential security risks by analyzing system activities and network configurations.

## 🚀 Features

- **Network Connection Analysis**: Lists active network connections.
- **Process Monitoring**: Displays currently running processes and their details.
- **Port Scanning**: Detects open ports on the system.
- **SSH Brute-Force Detection**: Identifies potential brute-force attacks on SSH services.

## 🛠️ Installation

Clone the repository and install the dependencies:

```bash
git clone https://github.com/frknclkkk/VM-SECURITY-TOOL
cd VM-Security-Tool
python3 -m venv venv
source venv/bin/activate 
pip install -r /VM-SECURITY-TOOL/vm_security_tool.egg-info/requires.txt 

```

## ▶️ Usage

Run the main scanner script:

```bash
python3 -m vm_security_tool.cli
```

The tool will begin scanning your system and display results in the terminal.

## 📁 Project Structure

- 'cli.py': Main application script.
- '.gitignore': Files and directories excluded from Git.
- 'README.md': Project documentation and usage guide.

## ✅ Requirements

- Python 3.8 or higher
- Linux based VM environment
- Internet access (for some network features)

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

> ⚠️ Disclaimer: This tool is intended for educational and authorized use only. Do not use it to scan systems without permission.
