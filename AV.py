import os
import zipfile
import logging
from datetime import datetime

# List of malware-related keywords (as defined in the previous steps)
malware_keywords = [
    "backdoor", "ransomware", "trojan", "spyware", "adware", "rootkit", "virus", 
    "worm", "botnet", "keylogger", "downloader", "hijacker", "exploit", "cracker",
    "payload", "cryptolocker", "cryptominer", "phishing", "fraud", "malicious", 
    "fake", "dropper", "cryptojacker", "zbot", "emotet", "mirai", "coinminer", 
    "banker", "apt", "injector", "fud", "trojanspy", "wannacry", "ryuk", "shifu",
    "conficker", "blaster", "sasser", "breach", "bruteforce", "exfiltration", 
    "zeroday", "backdoortrojan", "malbot", "hacktool", "spybot", "mimicry", 
    "packetsniffer", "inject", "socialengineering", "dos", "ddos", "payload", 
    "wiper", "pony", "kazy", "dridex", "tega", "badusb", "trojans", "p2p", "hijack",
    "exploits", "shellcode", "injectable", "malicioussoftware", "trojandownloader", 
    "malscript", "rat", "eternalblue", "darkside", "kovter", "triton", "sunburst", 
    "redoctober", "eicar", "fileless", "imposter", "keylogger", "metasploit", "cobaltstrike",
    "hacker", "exploitkit", "zero-day", "reverse-shell", "payload-delivery", "exfil",
    "backdoor-shell", "remote-access", "social-engineering", "cross-site-scripting", "sql-injection",
    "malware-as-a-service", "remote-code-execution", "cross-site-request-forgery", "phishing", 
    "dns-tunneling", "smishing", "vishing", "drive-by-download", "remote-attack", "brute-force",
    "cyber-attack", "advanced-persistent-threat", "conficker", "cryptoworm", "doxware", 
    "dns-poisoning", "fraudulent", "keygen", "stealth-virus", "packer", "trojan-dropper", "dropper", 
    "rootkit-loader", "web-shell", "dirty-cow", "mimikatz", "backdoor-trojan", "infostealer",
    "jacking", "cookie-stealing", "cryptojacking", "fishing", "pass-the-hash", "credential-stuffing",
    "hacking", "exploited", "overflows", "buffer-overflow", "system-compromise", "worm-virus", 
    "mobile-trojan", "redirection", "ip-spoofing", "ddos-bot", "android-malware", "ios-malware", 
    "android-trojan", "ransom-trojan", "advanced-malware", "stealthy-malware", "escalation",
    "cryptolocker", "wannacrypt", "ransomware-v2", "malvertising", "cryptolocker-variant", 
    "wannacry-exploit", "hacking-exploit", "root-exploit", "webshell", "mining-malware", "coin-hive",
    "miner-trojan", "self-replicating", "worm-ransomware", "webshell-backdoor", "trojan-spreader", 
    "malicious-ads", "torrent-malware", "attack-vector", "remote-shell", "android-rootkit", "pdf-trojan",
    "worm-backdoor", "cryptovirus", "fake-crypto", "malicious-script", "user-agent-spoofing", 
    "advanced-botnet", "sockpuppet", "fraudbot", "keyloggers", "zero-day-exploit", "spybot", 
    "blackhat", "injector-trojan", "adware-trojan", "proxy-malware", "advanced-adware", "web-shell",
    "fake-antivirus", "android-backdoor", "network-sniffer", "drive-by-download", "domain-spoofing", 
    "ad-fraud", "remote-admin-tool", "fud-malware", "trojanized", "hacktool", "autodialer", "downloader-trojan",
    "botnet-trojan", "polymorphic-malware", "cryptojacking", "phishing-trojan", "hybrid-malware",
    "social-media-hacker", "system-virus", "javascript-exploit", "adware-spyware", "no-restore-virus",
    "script-kiddie", "remote-backdoor", "spoofed-file", "spoofed-trojan", "mbr-trojan", "remote-trojan",
    "bot-exploit", "cve-2017-5638", "ghost-keylogger", "ransom-keylogger", "targeted-trojan", 
    "usb-hijacker", "iphone-malware", "windows-spyware", "stuxnet", "android-virus", "malicious-payload",
    "vulnerable-code", "credential-theft", "tor-exploit", "cybercrime", "hack-exploit", "proxy-exploit", 
    "blackhat-tool", "web-scraper", "dga", "bruteforce-tool", "ip-tunneling", "xss-exploit", "shellcode-exploit",
    "harvester", "hexadecimal-exploit", "doomsday-virus", "file-infection", "blacklist-trojan", "win32-malware",
    "backdoor-cmd", "cookie-stealer", "mining-rat", "wiper-virus", "webshell-trojan", "malvertising",
    "root-exploit", "keylogger-exploit", "trojan-url", "backdoor-keylogger", "ad-injection", "data-stealing",
    "packet-injection", "traffic-spoofing", "dns-exploit", "network-injection", "browser-exploit",
    "bypass-exploit", "credential-exfiltration", "payload-exfiltration", "malicious-exploit",
    "file-injector", "trojan-backdoor", "android-exploit", "os-exploit", "rpc-exploit", "dos-exploit", 
    "trojan-payload", "exfil-trojan", "root-exploit", "imposter-virus", "mimicry-malware"
]

# Set up logging
log_filename = f"malware_scan_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Create a ZIP file to store malware-related .exe, .sys, and .dll files
zip_filename = f"malware_files_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"

def search_keywords_in_file(file_path):
    """Search for malware keywords in the binary content of a file."""
    found_keywords = []
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
            for keyword in malware_keywords:
                keyword_bytes = keyword.encode('utf-8')
                if keyword_bytes in content:
                    found_keywords.append(keyword)
                    logging.info(f"Malware keyword '{keyword}' found in file: {file_path}")
    except Exception as e:
        logging.error(f"Error reading {file_path}: {e}")
    return found_keywords

def calculate_severity(keyword_count_in_file):
    """Calculate risk severity for a file based on the number of keywords found."""
    if keyword_count_in_file >= 6:
        return "High Risk"
    elif 3 <= keyword_count_in_file < 6:
        return "Medium Risk"
    elif 1 <= keyword_count_in_file < 3:
        return "Low Risk"
    else:
        return "No Risk"

def scan_for_malware_keywords(directory_path):
    """Scan .exe, .sys, .dll files in a directory for malware-related keywords and add them to a ZIP file."""
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if file.lower().endswith(('.exe', '.sys', '.dll')):  # Scan .exe, .sys, and .dll files
                    file_path = os.path.join(root, file)
                    found_keywords = search_keywords_in_file(file_path)
                    if found_keywords:
                        severity = calculate_severity(len(found_keywords))
                        logging.info(f"File: {file_path} | Keywords Found: {len(found_keywords)} | Severity: {severity}")
                        try:
                            zipf.write(file_path, os.path.relpath(file_path, directory_path))
                            logging.info(f"Added {file_path} to the ZIP archive.")
                        except Exception as e:
                            logging.error(f"Error adding {file_path} to the ZIP archive: {e}")

def choose_scan_option():
    """Prompt the user to choose between scanning a specific file or an entire drive."""
    print("Please choose an option:")
    print("1. Scan a specific .exe, .sys, or .dll file")
    print("2. Scan an entire drive or directory")
    choice = input("Enter your choice (1 or 2): ").strip()
    
    if choice == "1":
        file_path = input("Enter the full path of the .exe, .sys, or .dll file: ").strip()
        if os.path.isfile(file_path) and file_path.lower().endswith(('.exe', '.sys', '.dll')):
            scan_for_malware_keywords(file_path)
        else:
            print("Invalid file path. Please ensure it is a valid .exe, .sys, or .dll file.")
    
    elif choice == "2":
        directory_path = input("Enter the directory to scan (e.g., C:\\Users): ").strip()
        if os.path.isdir(directory_path):
            scan_for_malware_keywords(directory_path)
        else:
            print("Invalid directory path. Please ensure it is a valid directory.")
    
    else:
        print("Invalid choice. Please enter 1 or 2.")

def main():
    choose_scan_option()

if __name__ == "__main__":
    main()

