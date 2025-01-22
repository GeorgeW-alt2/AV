import os
import logging
import psutil
import zipfile
from datetime import datetime
from tqdm import tqdm  # Import tqdm for the progress bar

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

# Directory to save the dumps
dump_dir = "process_dumps"
os.makedirs(dump_dir, exist_ok=True)

# Create a ZIP file to store malware-related process memory dumps
zip_filename = f"malware_memory_dumps_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"

def search_keywords_in_memory(memory_content):
    """Search for malware keywords in the memory content (byte sequence)."""
    found_keywords = []
    try:
        for keyword in malware_keywords:
            keyword_bytes = keyword.encode('utf-8')
            if keyword_bytes in memory_content:
                found_keywords.append(keyword)
                logging.info(f"Malware keyword '{keyword}' found in memory.")
    except Exception as e:
        logging.error(f"Error scanning memory: {e}")
    return found_keywords

def dump_process_memory(pid, process_name):
    """Dump the memory of a process to a binary file and add it to the ZIP archive."""
    try:
        process = psutil.Process(pid)
        memory_content = b""
        for map in process.memory_maps():
            # Check if the map has a readable path
            if map.path and os.access(map.path, os.R_OK):
                try:
                    # Open the memory map file and read its content
                    with open(map.path, 'rb') as mem_file:
                        memory_content += mem_file.read()
                except Exception as e:
                    logging.error(f"Error reading memory map {map.path}: {e}")

        # Create a file to dump the memory content
        dump_filename = os.path.join(dump_dir, f"{process_name}_{pid}_memory_dump.bin")
        with open(dump_filename, 'wb') as dump_file:
            dump_file.write(memory_content)
            logging.info(f"Memory dump for PID {pid} saved to {dump_filename}")

        # Add the dump file to the ZIP archive
        with zipfile.ZipFile(zip_filename, 'a', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(dump_filename, os.path.basename(dump_filename))  # Add file to ZIP
            logging.info(f"Added {dump_filename} to the ZIP archive.")

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        logging.error(f"Cannot access process {pid} memory: {e}")

def scan_process_memory(pid):
    """Scan the memory of a process for malware-related keywords."""
    try:
        process = psutil.Process(pid)
        process_name = process.name()
        memory_content = b""
        for map in process.memory_maps():
            # Check if the map has a readable path
            if map.path and os.access(map.path, os.R_OK):
                try:
                    # Open the memory map file and read its content
                    with open(map.path, 'rb') as mem_file:
                        memory_content += mem_file.read()
                except Exception as e:
                    logging.error(f"Error reading memory map {map.path}: {e}")

        # Search for malware keywords in the collected memory content
        found_keywords = search_keywords_in_memory(memory_content)
        if found_keywords:
            severity = calculate_severity(len(found_keywords))
            logging.info(f"Process ID {pid} | Keywords Found: {len(found_keywords)} | Severity: {severity}")
            
            # Dump the process memory and add to ZIP archive if malware is found
            dump_process_memory(pid, process_name)

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        logging.error(f"Cannot access process {pid} memory: {e}")

def calculate_severity(keyword_count_in_memory):
    """Calculate risk severity for a process based on the number of keywords found in its memory."""
    if keyword_count_in_memory >= 6:
        return "High Risk"
    elif 3 <= keyword_count_in_memory < 6:
        return "Medium Risk"
    elif 1 <= keyword_count_in_memory < 3:
        return "Low Risk"
    else:
        return "No Risk"

def scan_all_processes():
    """Scan all running processes for malware-related keywords in their memory."""
    for proc in tqdm(psutil.process_iter(['pid', 'name']), desc="Scanning processes", unit="process"):
        scan_process_memory(proc.info['pid'])

def choose_scan_option():
    """Prompt the user to choose between scanning a specific process or all processes."""
    print("Please choose an option:")
    print("1. Scan a specific process's memory")
    print("2. Scan all running processes' memory")
    choice = input("Enter your choice (1 or 2): ").strip()
    
    if choice == "1":
        pid = input("Enter the process ID (PID) to scan: ").strip()
        try:
            pid = int(pid)
            scan_process_memory(pid)
        except ValueError:
            print("Invalid PID. Please enter a valid integer.")
    
    elif choice == "2":
        scan_all_processes()
    
    else:
        print("Invalid choice. Please enter 1 or 2.")

def main():
    choose_scan_option()

if __name__ == "__main__":
    main()
