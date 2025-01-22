import os
import logging
from datetime import datetime
from tqdm import tqdm  # For progress bar
import zipfile

# Set up logging
log_filename = f"non_utf8_scan_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Create a ZIP file to store files with non-UTF-8 characters
zip_filename = f"non_utf8_files_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"

def contains_non_utf8(file_path):
    """Check if the file contains non-UTF-8 characters."""
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
            try:
                # Attempt to decode the file as UTF-8
                content.decode('utf-8')
            except UnicodeDecodeError as e:
                # If a UnicodeDecodeError is raised, the file contains invalid UTF-8 bytes
                logging.info(f"Non-UTF-8 character found in file: {file_path}")
                return True
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
    return False

def scan_exe_files_for_non_utf8(directory_path):
    """Scan .exe files in the specified directory for non-UTF-8 characters."""
    exe_files = [os.path.join(root, file) for root, dirs, files in os.walk(directory_path) for file in files if file.lower().endswith('.exe')]
    
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for exe_file in tqdm(exe_files, desc="Scanning .exe files", unit="file"):
            if contains_non_utf8(exe_file):
                try:
                    # If the file contains non-UTF-8 characters, add it to the ZIP archive
                    zipf.write(exe_file, os.path.relpath(exe_file, directory_path))
                    logging.info(f"Added non-UTF-8 file {exe_file} to the ZIP archive.")
                except Exception as e:
                    logging.error(f"Error adding {exe_file} to the ZIP archive: {e}")

def choose_scan_option():
    """Prompt the user to choose between scanning a specific file or an entire directory."""
    print("Please choose an option:")
    print("1. Scan a specific .exe file")
    print("2. Scan an entire directory for .exe files with non-UTF-8 characters")
    choice = input("Enter your choice (1 or 2): ").strip()
    
    if choice == "1":
        file_path = input("Enter the full path of the .exe file to scan: ").strip()
        if os.path.isfile(file_path) and file_path.lower().endswith('.exe'):
            if contains_non_utf8(file_path):
                logging.info(f"Non-UTF-8 characters found in {file_path}.")
            else:
                print(f"{file_path} is UTF-8 encoded.")
        else:
            print("Invalid file path. Please ensure it is a valid .exe file.")
    
    elif choice == "2":
        directory_path = input("Enter the directory to scan (e.g., C:\\Users): ").strip()
        if os.path.isdir(directory_path):
            scan_exe_files_for_non_utf8(directory_path)
        else:
            print("Invalid directory path. Please ensure it is a valid directory.")
    
    else:
        print("Invalid choice. Please enter 1 or 2.")

def main():
    choose_scan_option()

if __name__ == "__main__":
    main()
