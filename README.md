# 🔍 Sensitive Data Scanner

A lightweight PowerShell script designed for scanning directories to identify potentially sensitive files based on keyword patterns, file types, and known configuration or credential storage formats. Perfect for red teamers, penetration testers, and sysadmins.

---

## ⚡ Features

- 🔑 Searches for **sensitive keywords** inside files (`password`, `token`, `api_key`, etc.)
- 🗂 Matches **filenames** against known patterns (`creds`, `secret`, `login`, etc.)
- 🔒 Flags **special files** like:
  - `web.config`, `unattend.xml`, `.env`, `id_rsa`, `vault.db`
  - Secrets/configs for AWS, Azure, GCP, Docker, Jenkins, Ansible, Terraform, and more
- 📁 Recursively scans directories and allows for **exclusions**
- 📤 Exports results in `.csv`, `.json`, `.html`, or `.txt`

---

## 📦 Usage

```powershell
.\SensitiveScan.ps1 `
  -SearchPaths "C:\","H:\" `
  -ExcludePaths "C:\Users\C3rb3rus\","H:\test" `
  -IncludeSensitiveFilenames `
  -IncludeSpecialFiles `
  -VerboseOutput `
  -ExportFormat "csv" `
  -ExportPath "C:\Users\Public\scan_results.csv"
````

---

## 🎛 Parameters

| Parameter                    | Description                                                                 |
| ---------------------------- | --------------------------------------------------------------------------- |
| `-SearchPaths`               | Array of root directories to recursively scan. Defaults to `C:\`            |
| `-ExcludePaths`              | Array of directories to exclude from scanning.                              |
| `-IncludeSensitiveFilenames` | Enable scanning for suspicious filenames like `password.txt`, `creds.xml`   |
| `-IncludeSpecialFiles`       | Enable matching against known sensitive file types (e.g., `.env`, `id_rsa`) |
| `-VerboseOutput`             | Display per-file scanning progress                                          |
| `-ExportFormat`              | Output format: `csv`, `json`, `html`, or `txt`                              |
| `-ExportPath`                | Full file path to export scan results                                       |

---

## 📁 Output Example

Each match will be shown with:

* Full path of the file
* Reason for detection (`Filename contains`, `Special file match`, or `Keyword match`)

Example output in PowerShell:

```
File                                     Reason
----                                     ------
C:\Users\Public\creds.txt                 Filename contains 'creds'
H:\backup\web.config                      Special file match: 'web.config'
C:\Users\Public\Desktop\notes.txt         Keyword match: 'password'
```

---

## 📤 Export Formats

| Format | Example Output                    |
| ------ | --------------------------------- |
| `csv`  | Structured table for spreadsheets |
| `json` | Structured JSON array             |
| `html` | Webpage-style table report        |
| `txt`  | Formatted plain-text table        |

---
