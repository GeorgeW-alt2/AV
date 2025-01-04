import os
import shutil
from datetime import datetime

# Define the patterns to look for
SUSPICIOUS_KEYWORDS = ["shell", "socket"]
MAX_SAFE_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
QUARANTINE_DIR = "quarantine"
LOG_FILE = "quarantine_log.txt"

def create_quarantine_directory():
    """
    Ensure the quarantine directory exists.
    """
    if not os.path.exists(QUARANTINE_DIR):
        os.makedirs(QUARANTINE_DIR)

def log_quarantine(filepath):
    """
    Log quarantined file details into a log file.
    """
    with open(LOG_FILE, "a") as log:
        log.write(f"{datetime.now()}: Quarantined {filepath}\n")

def quarantine_file(filepath):
    """
    Move a file to the quarantine directory and log the action.
    """
    create_quarantine_directory()
    try:
        # Move the file to the quarantine directory
        quarantined_path = os.path.join(QUARANTINE_DIR, os.path.basename(filepath))
        shutil.copy(filepath, quarantined_path)
        print(f"[!] Quarantined file: {filepath}")
        log_quarantine(filepath)
    except Exception as e:
        print(f"[!] Error quarantining file {filepath}: {e}")

def scan_file(filepath):
    """
    Scan a file for suspicious patterns and quarantine if both 'shell' and 'socket' are detected.
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()
        
        # Check for both "shell" and "socket" in the content
        if "shell" in content and "socket" in content:
            quarantine_file(filepath)
        
    except Exception as e:
        print(f"[!] Error scanning file {filepath}: {e}")

def scan_directory(directory):
    """
    Scan all `.exe` files in a directory for suspicious patterns.
    """
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            # Only scan `.exe` files
            if not file.lower().endswith(".exe"):
                continue
            
            # Skip large files for performance reasons
            if os.path.getsize(filepath) > MAX_SAFE_FILE_SIZE:
                print(f"[!] Skipping large file: {filepath}")
                continue
            
            scan_file(filepath)

if __name__ == "__main__":
    directory_to_scan = input("Enter the directory to scan: ").strip()
    
    if os.path.exists(directory_to_scan):
        print(f"Scanning directory: {directory_to_scan}")
        scan_directory(directory_to_scan)
    else:
        print(f"[!] Directory does not exist: {directory_to_scan}")
