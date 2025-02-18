#include <windows.h>
#include <iostream>
#include <string>

class NetworkBlocker {
private:
    bool executeCommand(const std::string& command) {
        // Create pipe for reading command output
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = TRUE;
        sa.lpSecurityDescriptor = NULL;

        HANDLE hReadPipe, hWritePipe;
        if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
            std::cerr << "Failed to create pipe" << std::endl;
            return false;
        }

        // Set up process info
        STARTUPINFOA si = {0};
        si.cb = sizeof(STARTUPINFOA);
        si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
        si.wShowWindow = SW_HIDE;
        si.hStdOutput = hWritePipe;
        si.hStdError = hWritePipe;

        PROCESS_INFORMATION pi = {0};

        // Create process
        if (!CreateProcessA(
            NULL,
            (LPSTR)command.c_str(),
            NULL,
            NULL,
            TRUE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi
        )) {
            std::cerr << "Failed to create process. Error: " << GetLastError() << std::endl;
            CloseHandle(hReadPipe);
            CloseHandle(hWritePipe);
            return false;
        }

        // Wait for process to finish
        WaitForSingleObject(pi.hProcess, INFINITE);

        // Get exit code
        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);

        // Clean up
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);

        return exitCode == 0;
    }

public:
    bool blockNetworkTraffic() {
        // Block outbound traffic using netsh
        std::string command = "netsh advfirewall firewall add rule name=\"BlockAll\" dir=out action=block enable=yes";
        return executeCommand(command);
    }

    bool unblockNetworkTraffic() {
        // Remove blocking rule
        std::string command = "netsh advfirewall firewall delete rule name=\"BlockAll\"";
        return executeCommand(command);
    }
};

int main() {
    try {
        std::cout << "Initializing network blocker (requires admin rights)..." << std::endl;
        NetworkBlocker blocker;

        std::cout << "Blocking network traffic..." << std::endl;
        if (blocker.blockNetworkTraffic()) {
            std::cout << "Network traffic blocked. Press Enter to unblock..." << std::endl;
            std::cin.get();

            if (blocker.unblockNetworkTraffic()) {
                std::cout << "Network traffic unblocked." << std::endl;
            } else {
                std::cerr << "Failed to unblock network traffic." << std::endl;
            }
        } else {
            std::cerr << "Failed to block network traffic." << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
