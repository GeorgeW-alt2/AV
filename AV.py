import os
import shutil
import psutil
from datetime import datetime

# Define the patterns to look for
SUSPICIOUS_KEYWORDS = ["shell", "socket"]
MAX_SAFE_FILE_SIZE = 15 * 1024 * 1024  # 15 MB
QUARANTINE_DIR = "quarantine"
LOG_FILE = "quarantine_log.txt"

def create_quarantine_directory():
    """
    Ensure the quarantine directory exists.
    """
    if not os.path.exists(QUARANTINE_DIR):
        os.makedirs(QUARANTINE_DIR)

def log_quarantine(filepath, action):
    """
    Log quarantined file details into a log file.
    """
    with open(LOG_FILE, "a") as log:
        log.write(f"{datetime.now()}: {action} {filepath}\n")

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
        log_quarantine(filepath, "Quarantined")
        
        # After quarantine, delete the original file
        os.remove(filepath)
        print(f"[!] Deleted original file: {filepath}")
        log_quarantine(filepath, "Deleted")
        
    except Exception as e:
        print(f"[!] Error quarantining/deleting file {filepath}: {e}")

def kill_process(filepath):
    """
    Kill any processes associated with the suspicious file.
    """
    try:
        # Get the process ID (PID) for any process with the filename
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            if proc.info['exe'] and filepath.lower() == proc.info['exe'].lower():
                print(f"[!] Killing process: {proc.info['pid']} running {proc.info['exe']}")
                proc.terminate()  # Try to kill the process
                proc.wait()  # Wait for the process to terminate
                print(f"[!] Process killed: {proc.info['pid']}")
                log_quarantine(filepath, f"Killed process {proc.info['pid']}")
                break
    except psutil.NoSuchProcess as e:
        print(f"[!] Process not found for {filepath}: {e}")
    except psutil.AccessDenied as e:
        print(f"[!] Access denied when trying to kill process {filepath}: {e}")
    except Exception as e:
        print(f"[!] Error killing process for {filepath}: {e}")

def scan_file(filepath):
    """
    Scan a file for suspicious patterns, quarantine, delete it, and kill associated processes if detected.
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()
        
        # Check for both "shell" and "socket" in the content
        if "shell" in content and "socket" in content:
            print(f"[!] Suspicious file detected: {filepath}")
            kill_process(filepath)  # Kill any running process associated with the file
            quarantine_file(filepath)  # Quarantine and delete the file
        
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
