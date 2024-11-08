# CodeScanningSuite
SAST, DAST, and custom code scanning to test security gaps



# DAST/SAST Testing Suite

## Overview
This suite provides dynamic and static analysis capabilities to identify security vulnerabilities in web applications, both at the code and runtime levels. It helps uncover common issues, such as SQL Injection, XSS, insecure configurations, and missing session management controls.

## Features
- **Static Analysis (SAST)**: Scans code for hardcoded credentials, insecure functions, and configuration issues.
- **Dynamic Analysis (DAST)**: Tests runtime security, simulating SQL Injection, XSS attacks, and CSRF token checks.
- **Risk Scoring and Compliance Mapping**: Aligns findings with OWASP Top 10 and CWE standards, and scores vulnerabilities for prioritization.
- **Baseline Tracking**: Archives reports for historical comparison, visualizing risk trends over time.

## Requirements
- **Python 3.8+**
- Install dependencies using `requirements.txt`:
    ```bash
    pip install -r requirements.txt
    ```

## Installation
1. **Clone the Repository**:
    ```bash
    git clone https://github.com/your-repository/dast-sast-testing-suite.git
    cd dast-sast-testing-suite
    ```

2. **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3. **Configure Settings**:
    - Open `config.json` to specify target URLs, source code paths, and enable specific DAST and SAST checks.

## Usage
1. **Run Static Analysis (SAST)**:
    ```bash
    python sast_analyzer.py
    ```
   - This script analyzes source code for hardcoded credentials, insecure configurations, and other vulnerabilities.

2. **Run Dynamic Analysis (DAST)**:
    ```bash
    python dast_scanner.py
    ```
   - This script performs runtime vulnerability scanning, including attack simulations and session management checks.

3. **Generate Vulnerability Report**:
    ```bash
    python report_generator.py
    ```
   - Generates a report with risk scores, compliance mappings, and remediation guidance in `dast_sast_report.txt` and `dast_sast_report.json`.

## Configuration
- **config.json**: Stores configuration for URLs, source code paths, and DAST/SAST settings.
    - **sast_settings**: Enables checks for injections, hardcoded credentials, and insecure configurations.
    - **dast_settings**: Activates runtime scans and attack simulations for vulnerabilities.
    - **baseline_tracking**: Enables report history tracking to identify security drift.

## Advanced Features
1. **Compliance Mapping with OWASP and CWE Standards**:
   - Each vulnerability is mapped to relevant standards, aiding structured remediation.

2. **Risk Scoring and Trend Visualization**:
   - Risk scoring prioritizes critical issues, and visual trend tracking helps monitor security improvements.

3. **Baseline Tracking**:
   - Maintains an archive of reports, allowing for historical comparisons to assess security drift.

## Example Configuration and Sample Output
- **config.json** (Example):
    ```json
    {
        "target_urls": ["https://example.com"],
        "source_code_path": "path/to/source_code",
        "sast_settings": {
            "scan_for_injections": true,
            "hardcoded_credential_check": true
        },
        "dast_settings": {
            "runtime_vulnerability_scan": true,
            "attack_simulation": ["sql_injection", "xss"]
        }
    }
    ```

- **Sample Output (dast_sast_report.txt)**:
    ```
    DAST/SAST Security Report
    =============================
    Total Vulnerabilities: 3
    Total Risk Score: 22

    Description: SQL Injection vulnerability detected in login form.
    Severity: Critical
    Risk Score: 30
    Compliance: A1 - Injection
    Recommendation: Use parameterized queries to prevent SQL Injection.
    ```

## License
This project is licensed under the MIT License.

## Support
For issues or support, please open an issue on the GitHub repository.
