
# report_generator.py - Enhanced Vulnerability Reporting, Compliance Mapping, and Baseline Tracking for DAST/SAST Suite

import json
import os
import matplotlib.pyplot as plt

# Define scoring criteria, compliance mappings, and risk levels
SEVERITY_SCORES = {
    "critical": 10,
    "high": 7,
    "medium": 5,
    "low": 2,
}
COMPLIANCE_MAPPING = {
    "sql_injection": "OWASP A1: Injection",
    "xss": "OWASP A7: Cross-Site Scripting (XSS)",
    "csrf_token_missing": "OWASP A8: Cross-Site Request Forgery (CSRF)",
    "secure_cookie": "OWASP A2: Broken Authentication"
}

# Calculate risk score based on severity and exploitability
def calculate_risk_score(vulnerabilities):
    total_score = 0
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "low")
        exploitability = vuln.get("exploitability", 1)
        score = SEVERITY_SCORES.get(severity, 2) * exploitability
        vuln["risk_score"] = score
        vuln["compliance_mapping"] = COMPLIANCE_MAPPING.get(vuln.get("type"), "Unknown")
        total_score += score
    return total_score

# Generate report with risk scores, compliance mappings, and remediation guidance
def generate_report(vulnerabilities, output_format="text"):
    report_data = {
        "total_vulnerabilities": len(vulnerabilities),
        "total_risk_score": calculate_risk_score(vulnerabilities),
        "vulnerabilities": vulnerabilities
    }
    
    if output_format == "text":
        with open("dast_sast_report.txt", "w") as report_file:
            report_file.write("DAST/SAST Security Report\n")
            report_file.write("============================\n")
            report_file.write(f"Total Vulnerabilities: {report_data['total_vulnerabilities']}\n")
            report_file.write(f"Total Risk Score: {report_data['total_risk_score']}\n\n")
            
            for vuln in vulnerabilities:
                report_file.write(f"Description: {vuln['description']}\n")
                report_file.write(f"Severity: {vuln['severity']}\n")
                report_file.write(f"Risk Score: {vuln['risk_score']}\n")
                report_file.write(f"Compliance: {vuln['compliance_mapping']}\n")
                report_file.write(f"Recommendation: {vuln['remediation']}\n\n")
    
    elif output_format == "json":
        with open("dast_sast_report.json", "w") as report_file:
            json.dump(report_data, report_file, indent=4)

# Baseline Tracking - Archive previous reports for comparison
def archive_report():
    if not os.path.exists("report_history"):
        os.makedirs("report_history")
    os.rename("dast_sast_report.txt", f"report_history/dast_sast_report_{len(os.listdir('report_history'))}.txt")

# Visualize Risk Scores Over Time
def visualize_risk_trend():
    scores = []
    for file in os.listdir("report_history"):
        with open(f"report_history/{file}", "r") as f:
            lines = f.readlines()
            for line in lines:
                if line.startswith("Total Risk Score:"):
                    scores.append(int(line.split(":")[1].strip()))

    plt.plot(scores, marker='o')
    plt.title("Risk Score Trend Over Time")
    plt.xlabel("Report History")
    plt.ylabel("Total Risk Score")
    plt.savefig("risk_trend.png")
    plt.show()

# Example vulnerability data for testing
vulnerabilities = [
    {
        "description": "SQL Injection vulnerability detected in login form.",
        "severity": "critical",
        "exploitability": 3,
        "type": "sql_injection",
        "remediation": "Use parameterized queries to prevent SQL Injection."
    },
    {
        "description": "No CSRF token detected in session.",
        "severity": "medium",
        "exploitability": 2,
        "type": "csrf_token_missing",
        "remediation": "Implement CSRF tokens in state-changing requests."
    }
]

# Generate example report and visualize trend
if __name__ == "__main__":
    generate_report(vulnerabilities, output_format="text")
    archive_report()  # Archive the report for baseline tracking
    visualize_risk_trend()  # Display trend over historical reports
