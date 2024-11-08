
# dast_scanner.py - Enhanced Dynamic Analysis Script for DAST/SAST Testing Suite

import json
import requests

# Load configuration from config.json
with open("config.json", "r") as config_file:
    config = json.load(config_file)

# Function to scan runtime vulnerabilities on target URLs
def scan_runtime_vulnerabilities(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print(f"[INFO] {url} is reachable and responding.")
        else:
            print(f"[WARNING] {url} returned status code {response.status_code}.")

        # SQL Injection simulation
        if "sql_injection" in config["dast_settings"]["attack_simulation"]:
            payload = {"id": "' OR '1'='1"}
            sql_response = requests.get(url, params=payload)
            if sql_response.status_code == 200 and "error" not in sql_response.text.lower():
                print(f"[ALERT] Possible SQL Injection vulnerability detected at {url}.")

        # XSS simulation
        if "xss" in config["dast_settings"]["attack_simulation"]:
            payload = {"search": "<script>alert('XSS')</script>"}
            xss_response = requests.get(url, params=payload)
            if "<script>alert('XSS')</script>" in xss_response.text:
                print(f"[ALERT] XSS vulnerability detected at {url}.")

        # XXE Injection simulation
        if "xxe" in config["dast_settings"]["attack_simulation"]:
            xml_payload = "<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"
            headers = {"Content-Type": "application/xml"}
            xxe_response = requests.post(url, data=xml_payload, headers=headers)
            if "root:" in xxe_response.text:
                print(f"[ALERT] XXE vulnerability detected at {url}.")

        # CORS Misconfiguration Check
        if "cors_misconfig" in config["dast_settings"]["attack_simulation"]:
            cors_response = requests.options(url, headers={"Origin": "http://evil.com"})
            if cors_response.headers.get("Access-Control-Allow-Origin") == "*":
                print(f"[ALERT] CORS Misconfiguration detected at {url}.")

    except Exception as e:
        print(f"[ERROR] Failed to reach {url}: {e}")

# Function to check for business logic flaws
def check_business_logic_flaws(url):
    print("[INFO] Testing for business logic flaws...")
    # Placeholder for logic flaw testing - simulate unexpected access patterns or privilege escalations
    privilege_escalation_payload = {"role": "admin"}  # Example payload
    response = requests.get(url, params=privilege_escalation_payload)
    if response.status_code == 200 and "Access Denied" not in response.text:
        print(f"[ALERT] Potential privilege escalation detected at {url}.")

# Function to check session management (e.g., CSRF tokens and secure cookies)
def check_session_management(url):
    response = requests.get(url)
    cookies = response.cookies

    # Check for CSRF token
    if config["dast_settings"]["session_management_checks"]:
        if not response.headers.get("Set-Cookie"):
            print(f"[WARNING] No CSRF token detected on {url}.")

    # Check for secure cookies
    for cookie in cookies:
        if not cookie.secure:
            print(f"[WARNING] Cookie {cookie.name} on {url} is not marked as secure.")

# Run DAST scan
def run_dast_scan():
    print("[INFO] Starting Enhanced Dynamic Analysis (DAST)...")
    for url in config["target_urls"]:
        scan_runtime_vulnerabilities(url)
        check_business_logic_flaws(url)
        check_session_management(url)

if __name__ == "__main__":
    run_dast_scan()
