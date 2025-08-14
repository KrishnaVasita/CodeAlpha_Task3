# CodeAlpha_Task3
Bug Bounty tool

 🛡️ Web App Bug Bounty Automation Tool

A Python-based automation tool for security researchers and bug bounty hunters.  
It scans a target URL for common vulnerabilities, misconfigurations, and open ports, and generates professional **HTML** and **JSON** reports.

 Features
- 🔍 Scans a target web application for common vulnerabilities
- 🌐 Supports **HTTP** and **HTTPS** targets
- ⚡ Optional **Nmap integration** for port scanning
- 📄 Generates reports in **HTML** and **JSON** formats
- 🖥️ Easy-to-use command-line interface
- 🛠️ Useful for bug bounty reconnaissance and reporting

 📦 Requirements
- Python 3.8+
- Install dependencies from `requirements.txt` 


🚀 Usage 
Basic scan:python3 web_app_bugbounty_tool.py -u https://testphp.vulnweb.com
Scan with Nmap integration: python3 web_app_bugbounty_tool.py -u https://testphp.vulnweb.com --nmap

Reports 
scan_report.json → JSON format output.
scan_report.html → HTML format output for browser viewing.

