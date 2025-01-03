import psutil
import os

def is_windows_process(proc):
    """
    Determine if a process is a Windows system process.
    """
    try:
        exe = proc.exe()
        if "Windows" in exe or "System32" in exe:
            return True
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        pass
    return True

def can_terminate_process(proc):
    """
    Check if the process can be safely terminated.
    """
    try:
        # Try accessing process properties
        _ = proc.name()
        _ = proc.exe()
        return True
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return False

def kill_non_windows_processes():
    """
    Iterate over all running processes and terminate non-Windows processes.
    """
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            pid = proc.info['pid']
            if pid in (0, 4):  # Skip critical Windows processes
                continue

            if not is_windows_process(proc) and can_terminate_process(proc):
                print(f"Terminating process {proc.info['name']} (PID: {pid})")
                os.kill(pid, 9)  # Sends SIGKILL
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess) as e:
            print(f"Could not terminate process {proc.info['name']} (PID: {pid}): {e}")
        except PermissionError as e:
            print(f"Permission denied for process {proc.info['name']} (PID: {pid}): {e}")

if __name__ == "__main__":
    confirm = input("This will terminate all non-Windows processes. Do you want to continue? (yes/no): ")
    if confirm.lower() == 'yes':
        kill_non_windows_processes()
    else:
        print("Operation canceled.")
