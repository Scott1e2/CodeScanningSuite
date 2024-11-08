
# sast_analyzer.py - Static Analysis Script for DAST/SAST Testing Suite

import os
import json

# Load configuration from config.json
with open("config.json", "r") as config_file:
    config = json.load(config_file)

# Function to analyze source code for hardcoded credentials and configuration issues
def analyze_code_for_issues(path):
    issues = []
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith(".py") or file.endswith(".js"):
                file_path = os.path.join(root, file)
                with open(file_path, "r") as code_file:
                    content = code_file.read()
                    
                    # Check for hardcoded credentials
                    if config["sast_settings"]["hardcoded_credential_check"]:
                        if "password" in content or "api_key" in content:
                            issues.append({
                                "description": f"Hardcoded credential found in {file}",
                                "severity": "high",
                                "file": file_path
                            })

                    # Check for insecure configuration
                    if config["sast_settings"]["configuration_checks"]:
                        if "eval(" in content or "exec(" in content:
                            issues.append({
                                "description": f"Insecure configuration in {file} (eval/exec usage)",
                                "severity": "medium",
                                "file": file_path
                            })

    return issues

# Generate report based on SAST findings
def generate_sast_report(issues):
    if not issues:
        print("[INFO] No issues found during static analysis.")
    else:
        print("[INFO] Static Analysis Report:")
        for issue in issues:
            print(f"File: {issue['file']} - {issue['description']} (Severity: {issue['severity']})")

# Run SAST scan
def run_sast_scan():
    print("[INFO] Starting Static Analysis (SAST)...")
    code_issues = analyze_code_for_issues(config["source_code_path"])
    generate_sast_report(code_issues)

if __name__ == "__main__":
    run_sast_scan()
