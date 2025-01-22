import os
import logging
import hashlib
from datetime import datetime
from tqdm import tqdm  # For progress bar
import zipfile

# Set up logging
log_filename = f"exe_similarity_scan_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Create a ZIP file to store similar .exe files
zip_filename = f"similar_exe_files_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"

# Size of the chunk to check for similarity (e.g., 256 bytes per chunk)
CHUNK_SIZE = 256

def get_file_hashes(file_path):
    """Generate a list of hash values for chunks of a file."""
    hashes = []
    try:
        with open(file_path, 'rb') as file:
            while chunk := file.read(CHUNK_SIZE):
                hash_object = hashlib.sha256(chunk)
                hashes.append(hash_object.hexdigest())  # Store the hash of each chunk
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
    return hashes

def compare_exe_files(file1_path, file2_path):
    """Compare two .exe files for similar byte patterns."""
    hashes1 = get_file_hashes(file1_path)
    hashes2 = get_file_hashes(file2_path)

    # Find the common hashes between two files
    common_hashes = set(hashes1) & set(hashes2)

    if len(common_hashes) > 3:  # Example threshold: files with more than 3 common chunks
        logging.info(f"Similar patterns found between {file1_path} and {file2_path}")
        return True
    return False

def scan_exe_files_for_similarity(directory_path):
    """Scan .exe files in the specified directory for similar patterns."""
    exe_files = [os.path.join(root, file) for root, dirs, files in os.walk(directory_path) for file in files if file.lower().endswith('.exe')]
    
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for i in tqdm(range(len(exe_files)), desc="Scanning .exe files", unit="file"):
            for j in range(i + 1, len(exe_files)):
                file1 = exe_files[i]
                file2 = exe_files[j]
                if compare_exe_files(file1, file2):
                    # If the files are similar, add them to the ZIP archive
                    try:
                        zipf.write(file1, os.path.relpath(file1, directory_path))
                        zipf.write(file2, os.path.relpath(file2, directory_path))
                        logging.info(f"Added similar files {file1} and {file2} to the ZIP archive.")
                    except Exception as e:
                        logging.error(f"Error adding {file1} or {file2} to the ZIP archive: {e}")

def choose_scan_option():
    """Prompt the user to choose between scanning a specific file or an entire directory."""
    print("Please choose an option:")
    print("1. Scan a specific .exe file")
    print("2. Scan an entire directory for similar .exe files")
    choice = input("Enter your choice (1 or 2): ").strip()
    
    if choice == "1":
        file_path = input("Enter the full path of the .exe file to scan: ").strip()
        if os.path.isfile(file_path) and file_path.lower().endswith('.exe'):
            # You can compare the given file with others (not implemented in this example)
            print(f"Scanning {file_path} for similar patterns...")
        else:
            print("Invalid file path. Please ensure it is a valid .exe file.")
    
    elif choice == "2":
        directory_path = input("Enter the directory to scan (e.g., C:\\Users): ").strip()
        if os.path.isdir(directory_path):
            scan_exe_files_for_similarity(directory_path)
        else:
            print("Invalid directory path. Please ensure it is a valid directory.")
    
    else:
        print("Invalid choice. Please enter 1 or 2.")

def main():
    choose_scan_option()

if __name__ == "__main__":
    main()
