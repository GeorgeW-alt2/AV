import os
import re
import logging
from datetime import datetime
from tqdm import tqdm  # For progress bar
import zipfile

# Set up logging
log_filename = f"polymorphic_code_scan_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Create a ZIP file to store files with suspected polymorphic code
zip_filename = f"polymorphic_code_files_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"

# Regular expressions to detect suspicious patterns commonly associated with polymorphic code
SUSPICIOUS_PATTERNS = [
    rb'\x89\xE5',  # Common instruction pattern (MOV ESP, EBP)
    rb'\x68[\x00-\xFF]{4}',  # PUSH with suspicious immediate value (often used for obfuscation)
    rb'\x6A[\x00-\xFF]{1}',  # PUSH with small immediate values (can indicate packing or polymorphism)
    rb'\x55\x8B\xEC',  # Prolog for some types of polymorphic code (MOV EBP, ESP and PUSH EBP)
    rb'[\x00-\x1F\x7F-\xFF]{4,}',  # Non-printable ASCII characters (could be an encrypted section)
    rb'\xC3',  # RET instruction (used in small obfuscations)
]

def contains_polymorphic_pattern(file_path):
    """Check if the file contains polymorphic code patterns."""
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
            
            # Look for suspicious patterns
            for pattern in SUSPICIOUS_PATTERNS:
                if re.search(pattern, content):
                    logging.info(f"Suspicious pattern found in file: {file_path}")
                    return True
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
    return False

def scan_exe_files_for_polymorphic_code(directory_path):
    """Scan .exe files in the specified directory for polymorphic code patterns."""
    exe_files = [os.path.join(root, file) for root, dirs, files in os.walk(directory_path) for file in files if file.lower().endswith('.exe')]
    
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for exe_file in tqdm(exe_files, desc="Scanning .exe files", unit="file"):
            if contains_polymorphic_pattern(exe_file):
                try:
                    # If the file is suspected to contain polymorphic code, add it to the ZIP archive
                    zipf.write(exe_file, os.path.relpath(exe_file, directory_path))
                    logging.info(f"Added suspected polymorphic code file {exe_file} to the ZIP archive.")
                except Exception as e:
                    logging.error(f"Error adding {exe_file} to the ZIP archive: {e}")

def choose_scan_option():
    """Prompt the user to choose between scanning a specific file or an entire directory."""
    print("Please choose an option:")
    print("1. Scan a specific .exe file")
    print("2. Scan an entire directory for polymorphic code in .exe files")
    choice = input("Enter your choice (1 or 2): ").strip()
    
    if choice == "1":
        file_path = input("Enter the full path of the .exe file to scan: ").strip()
        if os.path.isfile(file_path) and file_path.lower().endswith('.exe'):
            if contains_polymorphic_pattern(file_path):
                logging.info(f"Polymorphic code detected in {file_path}.")
            else:
                print(f"{file_path} does not contain polymorphic code.")
        else:
            print("Invalid file path. Please ensure it is a valid .exe file.")
    
    elif choice == "2":
        directory_path = input("Enter the directory to scan (e.g., C:\\Users): ").strip()
        if os.path.isdir(directory_path):
            scan_exe_files_for_polymorphic_code(directory_path)
        else:
            print("Invalid directory path. Please ensure it is a valid directory.")
    
    else:
        print("Invalid choice. Please enter 1 or 2.")

def main():
    choose_scan_option()

if __name__ == "__main__":
    main()
