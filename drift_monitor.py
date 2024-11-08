
# drift_monitor.py - Real-Time Drift Monitoring for DAST/SAST Testing Suite

import os
import time
import hashlib
import json
from logging_config import setup_logging
import logging

# Load configuration from config.json
with open("config.json", "r") as config_file:
    config = json.load(config_file)

# Initialize logging
setup_logging("drift_monitor.log")
logger = logging.getLogger(__name__)

# Function to calculate the hash of a file
def get_file_hash(file_path):
    hash_func = hashlib.md5()
    with open(file_path, "rb") as file:
        while chunk := file.read(4096):
            hash_func.update(chunk)
    return hash_func.hexdigest()

# Function to monitor a directory for changes
def monitor_directory(path, initial_hashes):
    current_hashes = {}
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = get_file_hash(file_path)
            current_hashes[file_path] = file_hash
            if file_path not in initial_hashes:
                logger.warning(f"New file detected: {file_path}")
            elif initial_hashes[file_path] != file_hash:
                logger.warning(f"File modified: {file_path}")

    removed_files = set(initial_hashes) - set(current_hashes)
    for removed_file in removed_files:
        logger.warning(f"File removed: {removed_file}")

    return current_hashes

# Function to initialize directory hashes
def initialize_directory_hashes(paths):
    file_hashes = {}
    for path in paths:
        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                file_hashes[file_path] = get_file_hash(file_path)
    return file_hashes

# Run real-time drift monitoring
def run_drift_monitor():
    monitored_paths = config["real_time_monitoring"]["code_paths_to_monitor"] + config["real_time_monitoring"]["config_paths_to_monitor"]
    logger.info("Starting real-time drift monitoring...")
    initial_hashes = initialize_directory_hashes(monitored_paths)
    
    while True:
        initial_hashes = monitor_directory(monitored_paths[0], initial_hashes)  # Update with detected changes
        time.sleep(10)  # Check every 10 seconds

if __name__ == "__main__":
    run_drift_monitor()
