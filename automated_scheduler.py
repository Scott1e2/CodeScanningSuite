
# automated_scheduler.py - Scheduler for DAST/SAST Testing Suite Scans and Monitoring

import time
import subprocess
from datetime import datetime
from logging_config import setup_logging
import logging

# Initialize logging
setup_logging("scheduler.log")
logger = logging.getLogger(__name__)

# Function to run a specified script and log the result
def run_script(script_path, description):
    logger.info(f"Running {description} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    result = subprocess.run(["python", script_path], capture_output=True, text=True)
    if result.returncode == 0:
        logger.info(f"{description} completed successfully.")
    else:
        logger.error(f"{description} failed with error: {result.stderr}")

# Schedule settings (intervals in seconds)
SCHEDULE = {
    "sast_scan": 86400,  # Run SAST once a day
    "dast_scan": 86400,  # Run DAST once a day
    "drift_monitor": 3600  # Run drift monitor every hour
}

# Paths to scripts
SCRIPTS = {
    "sast_scan": "sast_analyzer.py",
    "dast_scan": "dast_scanner.py",
    "drift_monitor": "drift_monitor.py"
}

# Main loop to manage scheduled tasks
def run_scheduler():
    logger.info("Starting automated scheduler for DAST/SAST suite...")
    last_run = {key: 0 for key in SCHEDULE}  # Store the last run time for each task

    while True:
        current_time = time.time()
        for task, interval in SCHEDULE.items():
            if current_time - last_run[task] >= interval:
                run_script(SCRIPTS[task], f"{task.replace('_', ' ').title()}")
                last_run[task] = current_time
        time.sleep(60)  # Check every minute

if __name__ == "__main__":
    run_scheduler()
