
# ThreatLens
### Automated Threat Intelligence and Incident Investigation Platform

ThreatLens is a Python-based cybersecurity dashboard that integrates with the VirusTotal API v3 to investigate Indicators of Compromise (IOCs), review threat intelligence, assess risk, and export investigation reports.

The project provides a SOC-inspired interface for security analysis and defensive cybersecurity learning.

## Features

- **Live Threat Intelligence:** Retrieve indicator analysis from VirusTotal API v3.
- **IOC Investigation:** Analyze IP addresses, domains, URLs, and file hashes.
- **Input Validation:** Validate indicator formats before sending API requests.
- **Threat Assessment:** Display malicious, suspicious, harmless, and undetected engine counts.
- **Risk Classification:** Categorize results by risk level using ThreatLens assessment logic.
- **Reputation Score:** Display a ThreatLens-calculated score out of 100.
- **Investigation Dashboard:** View summary statistics and recent investigation activity.
- **Investigation History:** Review records from the current application session.
- **Report Export:** Download investigation reports in CSV and JSON formats.
- **SOC-Inspired UI:** Use a dark security operations dashboard interface.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Application logic |
| Streamlit | Interactive web dashboard |
| VirusTotal API v3 | Threat intelligence |
| Requests | HTTP API communication |
| Pandas | Data processing and CSV exports |
| Plotly | Dashboard visualizations |
| python-dotenv | Environment variable management |

## Project Structure

```text
ThreatLens/
├── app.py
├── .env
├── .gitignore
├── README.md
└── venv/
```

**Security note:** `.env` and `venv/` are local files and should not be committed to GitHub.

## Prerequisites

- Kali Linux or another compatible Linux distribution
- Python 3.10 or later, compatible with installed dependencies
- Internet connection
- VirusTotal API key
- pip and Python virtual environment support

## Installation

### 1. Clone the repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd ThreatLens
```

Replace the placeholder with your actual repository URL.

### 2. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install streamlit requests pandas plotly python-dotenv
```

### 4. Configure the VirusTotal API key

Create a local `.env` file:

```bash
nano .env
```

Add your own API key:

```dotenv
VT_API_KEY=YOUR_VIRUSTOTAL_API_KEY
```

Replace the placeholder with your key. Never publish your actual API key, commit `.env`, or share it in screenshots or public repositories.

### 5. Launch the application

```bash
streamlit run app.py
```

Open the Local URL printed in the terminal, usually:

```text
http://localhost:8501
```

## How to Use

1. Launch ThreatLens.
2. Open **IOC Investigation** from the sidebar.
3. Select an indicator type: IP Address, Domain, URL, or File Hash.
4. Enter an indicator and submit it for analysis.
5. Review the threat assessment and detection statistics.
6. Open **Investigation History** to review recorded investigations.
7. Export records in CSV or JSON format.

For an initial connectivity test, you can investigate a known public IP such as `8.8.8.8`. Its reputation results may change over time.

## Testing

The following manual checks have been performed during development:

| Test | Result |
|---|---|
| Python syntax compilation | Passed |
| Live VirusTotal lookup for a public IP | Passed |
| Investigation result display | Passed |
| Investigation history display | Passed |
| CSV report download | Passed |
| JSON report download | Passed |

These results describe the checks performed during development, not a comprehensive automated test suite.

## Security Considerations

- Keep the VirusTotal API key in `.env`.
- Do not commit secrets or environment files.
- Respect VirusTotal API usage limits and terms.
- Treat external intelligence results as investigative evidence, not absolute proof.
- A zero-detection result does not guarantee that an indicator is safe.
- The ThreatLens reputation score is an application-calculated value, not an official VirusTotal score.
- Investigation history is stored in the current Streamlit session and is not a persistent database.
- Investigate only systems and indicators you are authorized to assess.

## Current Limitations

- Requires an internet connection for live VirusTotal lookups.
- API access and request limits depend on the VirusTotal account.
- Session history may not persist after a session resets.
- The current implementation does not use a persistent database or a full SIEM backend.

## Future Enhancements

- Persistent investigation storage using SQLite or PostgreSQL.
- Authentication and role-based access control.
- Automated scheduled threat-intelligence enrichment.
- Additional threat-intelligence providers.
- Investigation timelines and detailed incident reports.
- Automated unit and integration tests.
- Configurable alerting and incident-response workflows.

## Disclaimer

ThreatLens is an educational and defensive cybersecurity project intended for authorized threat intelligence and incident investigation. It does not guarantee that an indicator is malicious or safe. Users are responsible for complying with applicable laws, API terms, and organizational security policies.

## Author

**Pooja Bisht**

Cybersecurity Student | Aspiring Security Analyst

GitHub: [033618poojabisht-sketch](https://github.com/033618poojabisht-sketch)

---

*ThreatLens — Turning threat intelligence into actionable investigation insights.*
