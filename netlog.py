import psutil
import socket
import logging
from datetime import datetime
from collections import defaultdict

# Set up logging
log_filename = f"network_traffic_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Dictionary to hold processes and their network traffic
process_traffic = defaultdict(list)

def resolve_ip(ip_address):
    """Resolve an IP address to a hostname."""
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return ip_address  # If host name can't be resolved, return the IP address

def scan_network_connections():
    """Scan active network connections and map them to processes."""
    # Get all network connections
    connections = psutil.net_connections(kind='inet')
    
    for conn in connections:
        pid = conn.pid
        if pid is None:
            continue
        
        try:
            # Get process name based on PID
            process = psutil.Process(pid)
            process_name = process.name()
            process_id = process.pid
            
            # Get the local and remote IP and port
            local_ip, local_port = conn.laddr
            remote_ip, remote_port = conn.raddr if conn.raddr else ("", 0)
            
            # Resolve the IP to a hostname if possible
            resolved_ip = resolve_ip(remote_ip) if remote_ip else "N/A"
            
            # Log the connection information
            log_message = (f"Process: {process_name} (PID: {process_id}) - "
                           f"Local: {local_ip}:{local_port} -> Remote: {resolved_ip}:{remote_port}")
            logging.info(log_message)
            print(log_message)  # Also print to console
            
            # Map the IP to the process
            if remote_ip:
                process_traffic[resolved_ip].append(process_name)
        
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Handle any process errors (e.g., process terminated)
            continue

def display_process_ip_mapping():
    """Display processes and their associated IP addresses."""
    print("\nProcesses and their associated IPs:")
    for ip, processes in process_traffic.items():
        print(f"\nIP Address: {ip}")
        for process in set(processes):  # Remove duplicates
            print(f" - {process}")

def main():
    print("Scanning network traffic and associated processes...")
    scan_network_connections()
    display_process_ip_mapping()

if __name__ == "__main__":
    main()
