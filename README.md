# 🐍 Chainsaw Automator: Threat Hunting & Event Log Analysis

## 🎯 Project Overview

This Python utility automates the complex search and carving operations of **Chainsaw**, a high-performance Windows Event Log analysis tool developed by **WithSecure Labs**. The project's goal is to dramatically accelerate Digital Forensics and Incident Response (DFIR) tasks by moving beyond Chainsaw’s raw JSON output to generate structured, human-readable reports.

This tool is designed to help analysts and threat hunters efficiently identify suspicious activity, lateral movement, and attacker Tactics, Techniques, and Procedures (TTPs) across large volumes of `.evtx` files.

### Core Functionality
* **Automated Execution:** Executes Chainsaw searches for multiple **Event IDs** in a single run.
* **Data Consolidation:** Consumes raw JSON output, extracts key forensic fields, and aggregates data from multiple event log sources.
* **Structured Reporting:** Generates clean **CSV spreadsheets** (Simple or Expert format) and a statistical **TXT summary report** for immediate analysis.

---

## 🛠️ Technical Stack & Features

| Category | Component / Library | Purpose in Project |
| :--- | :--- | :--- |
| **Language** | Python 3.x | Core scripting language for automation and data manipulation. |
| **Core Tool** | Chainsaw.exe | High-speed executable for querying Windows Event Logs. ([Official GitHub Source](https://github.com/WithSecureLabs/chainsaw)) |
| **Modules** | `subprocess`, `json`, `csv` | Used to execute Chainsaw, capture its raw JSON output, and transform it into structured reporting formats. |
| **Data Structure** | **Logon Type Mapping** | Automatically translates numeric `LogonType` codes (e.g., `2`, `3`, `10`) into descriptive names (e.g., **Interactive**, **Network**, **RemoteInteractive**). |
| **Reporting** | **Statistical Summary** | Generates reports detailing event counts by ID, breakdown by logon type, and lists top-interacting user accounts. |

---

## ⚙️ Execution & Data Flow

### Prerequisites
* Python 3.x installed.
* **Chainsaw.exe** executable downloaded.
* Target Windows Event Log files (`.evtx`) collected.

### How to Run
1.  Navigate to the script's directory.
2.  Execute the Python script:
    ```bash
    python chainsaw_automator.py
    ```
3.  The tool will launch an **interactive CLI** to prompt for:
    * Path to `chainsaw.exe`.
    * Folder containing the `.evtx` files.
    * Selection of **Event IDs** to search (predefined categories or manual entry).
    * Desired CSV output format (Simple for quick review, Expert for comprehensive data).

### Output Artifacts
The tool creates a dedicated results folder containing:
1.  **Intermediate JSON Files:** Raw output for each `EventID` searched.
2.  **Summary CSV:** A consolidated spreadsheet of all extracted events, ready for filtering and correlation in tools like Excel or Splunk.
3.  **TXT Report:** A high-level forensic summary providing event statistics.
