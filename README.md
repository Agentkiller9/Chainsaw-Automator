# 💻 Automated Windows Event Log Analyzer (Chainsaw Automator)

## 🛡️ Project Overview

This Python utility automates the execution of **Chainsaw.exe**, a specialized command-line tool for carving and searching Windows Event Logs (`.evtx`). The goal of this project is to streamline the threat hunting process by enabling users to rapidly extract and consolidate security-relevant events from multiple log files into easily readable **CSV summaries** and **TXT reports**.

This tool significantly reduces the manual overhead associated with forensic log analysis, making it an essential component for effective Digital Forensics and Incident Response (DFIR) or Blue Team operations.

---

## 🛠️ Technical Stack & Features

| Category | Component / Library | Purpose in Project |
| :--- | :--- | :--- |
| **Language** | Python 3.x | Core scripting language for automation and data processing. |
| **Core Tool** | Chainsaw.exe | The underlying executable used for event log searching and carving. |
| **Data Processing** | `csv`, `json`, `os`, `pathlib` | Handling file system operations, reading raw JSON output from Chainsaw, and generating structured CSV reports. |
| **Functionality** | **Event ID Mapping** | Includes built-in mappings for common security events (Logon, Account Management, Process Creation) for quick selection. |
| **Output Formats** | **Simple/Expert CSV**, TXT Summary | Provides options for minimal-field output for quick review or comprehensive output for deep-dive analysis. |

---

## ⚙️ How It Works

1.  **Setup:** The script first interactively prompts the user for the paths to `chainsaw.exe`, the folder containing the raw `.evtx` files, and the desired output directory.
2.  **Event Selection:** The user selects events to search for, either by choosing predefined categories (e.g., all Logon events) or entering custom Event IDs.
3.  **Chainsaw Execution:** For each selected Event ID, the script executes `chainsaw search` command, piping the results directly into a structured **JSON file**.
4.  **Analysis & Consolidation:** After searching is complete, the script reads all generated JSON files, extracts key fields (Timestamp, User, Event ID, IP Address, Logon Type, etc.), and consolidates them.
5.  **Reporting:** Finally, it generates a comprehensive CSV file (either "Simple" or "Expert" format) and a statistical TXT summary report detailing event counts, user activity, and logon types.

---

## ▶️ Getting Started (Usage)

### Prerequisites
* Python 3.x installed.
* The **Chainsaw.exe** executable downloaded and accessible.
* Windows `.evtx` files collected and placed in a dedicated input folder.

### Running the Tool

1.  Clone the repository and navigate to the directory.
2.  Run the script from your command line:
    ```bash
    python chainsaw_automator.py
    ```
3.  Follow the interactive prompts to input file paths, select the desired event categories, and choose the final report format (Simple or Expert CSV).

### Example Output:
The script generates a final folder structure that includes:
* `[ServerName]_[EventID].json`: Raw search results from Chainsaw.
* `[OutputFileName].csv`: The consolidated, forensic-ready event spreadsheet.
* `[OutputFileName]_summary.txt`: A high-level report detailing event statistics and top users.
