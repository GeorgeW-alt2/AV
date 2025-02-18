#include <windows.h>
#include <tlhelp32.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <algorithm>

class SystemLogger {
private:
    std::ofstream logFile;
    std::string logPath;
    bool running;

    // Store process info for termination tracking
    struct ProcessInfo {
        std::string name;
        DWORD parentPID;
        std::string startTime;
    };
    std::map<DWORD, ProcessInfo> processMap;

    std::string getCurrentTimestamp() {
        auto now = std::time(nullptr);
        auto tm = *std::localtime(&now);
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }

    void logEvent(const std::string& eventType, const std::string& details, bool isTermination = false) {
        std::string timestamp = getCurrentTimestamp();
        std::string status = isTermination ? "TERMINATED" : "STARTED";
        std::string logEntry = "[" + timestamp + "] [" + eventType + "] [" + status + "] " + details;

        logFile << logEntry << std::endl;
        std::cout << logEntry << std::endl;
    }

    static DWORD WINAPI fileSystemMonitorThread(LPVOID param) {
        SystemLogger* logger = (SystemLogger*)param;
        char buffer[4096];
        DWORD bytesReturned;
        HANDLE hDir = CreateFileA(
            "C:\\",
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            NULL
        );

        if (hDir == INVALID_HANDLE_VALUE) {
            logger->logEvent("ERROR", "Failed to open directory for monitoring");
            return 1;
        }

        FILE_NOTIFY_INFORMATION* fni;
        while (logger->running) {
            if (ReadDirectoryChangesW(
                hDir,
                buffer,
                sizeof(buffer),
                TRUE,
                FILE_NOTIFY_CHANGE_FILE_NAME |
                FILE_NOTIFY_CHANGE_DIR_NAME |
                FILE_NOTIFY_CHANGE_ATTRIBUTES |
                FILE_NOTIFY_CHANGE_SIZE |
                FILE_NOTIFY_CHANGE_LAST_WRITE |
                FILE_NOTIFY_CHANGE_CREATION |
                FILE_NOTIFY_CHANGE_SECURITY,
                &bytesReturned,
                NULL,
                NULL)) {

                fni = (FILE_NOTIFY_INFORMATION*)buffer;
                do {
                    std::wstring wFileName(fni->FileName, fni->FileNameLength/sizeof(WCHAR));
                    std::string fileName(wFileName.begin(), wFileName.end());
                    std::string action;
                    bool isTermination = false;

                    switch (fni->Action) {
                        case FILE_ACTION_ADDED:
                            action = "Created: ";
                            break;
                        case FILE_ACTION_REMOVED:
                            action = "Deleted: ";
                            isTermination = true;
                            break;
                        case FILE_ACTION_MODIFIED:
                            action = "Modified: ";
                            break;
                        case FILE_ACTION_RENAMED_OLD_NAME:
                            action = "Renamed from: ";
                            isTermination = true;
                            break;
                        case FILE_ACTION_RENAMED_NEW_NAME:
                            action = "Renamed to: ";
                            break;
                        default:
                            action = "Unknown action on: ";
                    }

                    logger->logEvent("FILE", action + fileName, isTermination);

                    if (fni->NextEntryOffset == 0) break;
                    fni = (FILE_NOTIFY_INFORMATION*)((BYTE*)fni + fni->NextEntryOffset);
                } while (true);
            }
        }

        CloseHandle(hDir);
        return 0;
    }

    std::string getProcessName(DWORD processID) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return "<unknown>";

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(pe32);

        if (Process32FirstW(snapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == processID) {
                    CloseHandle(snapshot);
                    std::wstring wname = pe32.szExeFile;
                    return std::string(wname.begin(), wname.end());
                }
            } while (Process32NextW(snapshot, &pe32));
        }

        CloseHandle(snapshot);
        return "<unknown>";
    }

    static DWORD WINAPI processMonitorThread(LPVOID param) {
        SystemLogger* logger = (SystemLogger*)param;

        while (logger->running) {
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE) {
                logger->logEvent("ERROR", "Failed to create process snapshot");
                Sleep(1000);
                continue;
            }

            PROCESSENTRY32W pe32;
            pe32.dwSize = sizeof(pe32);
            std::map<DWORD, bool> currentProcesses;

            if (Process32FirstW(snapshot, &pe32)) {
                do {
                    currentProcesses[pe32.th32ProcessID] = true;

                    // Check for new processes
                    if (logger->processMap.find(pe32.th32ProcessID) == logger->processMap.end()) {
                        ProcessInfo info;
                        info.name = logger->getProcessName(pe32.th32ProcessID);
                        info.parentPID = pe32.th32ParentProcessID;
                        info.startTime = logger->getCurrentTimestamp();

                        std::stringstream ss;
                        ss << info.name << " (PID: " << pe32.th32ProcessID
                           << ", Parent PID: " << pe32.th32ParentProcessID << ")";

                        logger->processMap[pe32.th32ProcessID] = info;
                        logger->logEvent("PROCESS", ss.str());
                    }
                } while (Process32NextW(snapshot, &pe32));
            }

            // Check for terminated processes
            for (auto it = logger->processMap.begin(); it != logger->processMap.end();) {
                if (currentProcesses.find(it->first) == currentProcesses.end()) {
                    std::stringstream ss;
                    ss << it->second.name << " (PID: " << it->first
                       << ", Parent PID: " << it->second.parentPID
                       << ", Runtime: " << it->second.startTime << " to "
                       << logger->getCurrentTimestamp() << ")";

                    logger->logEvent("PROCESS", ss.str(), true);
                    it = logger->processMap.erase(it);
                } else {
                    ++it;
                }
            }

            CloseHandle(snapshot);
            Sleep(1000);
        }
        return 0;
    }

    static DWORD WINAPI registryMonitorThread(LPVOID param) {
        SystemLogger* logger = (SystemLogger*)param;
        std::map<std::string, std::string> regValues;

        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                       "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                       0, KEY_READ | KEY_NOTIFY, &hKey) == ERROR_SUCCESS) {

            // Initial scan of values
            char valueName[256];
            char valueData[1024];
            DWORD valueSize, dataSize, type;
            DWORD index = 0;

            while (RegEnumValueA(hKey, index++, valueName, &(valueSize = 256),
                               NULL, &type, (BYTE*)valueData, &(dataSize = 1024)) == ERROR_SUCCESS) {
                regValues[valueName] = std::string(valueData, dataSize);
            }

            HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
            while (logger->running) {
                if (RegNotifyChangeKeyValue(hKey, TRUE,
                    REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                    hEvent, TRUE) == ERROR_SUCCESS) {

                    if (WaitForSingleObject(hEvent, 1000) == WAIT_OBJECT_0) {
                        std::map<std::string, std::string> newValues;
                        index = 0;

                        while (RegEnumValueA(hKey, index++, valueName, &(valueSize = 256),
                                           NULL, &type, (BYTE*)valueData, &(dataSize = 1024)) == ERROR_SUCCESS) {
                            newValues[valueName] = std::string(valueData, dataSize);
                        }

                        // Check for added/modified values
                        for (const auto& pair : newValues) {
                            if (regValues.find(pair.first) == regValues.end()) {
                                logger->logEvent("REGISTRY", "Added: " + pair.first + " = " + pair.second);
                            } else if (regValues[pair.first] != pair.second) {
                                logger->logEvent("REGISTRY", "Modified: " + pair.first +
                                               " from '" + regValues[pair.first] +
                                               "' to '" + pair.second + "'");
                            }
                        }

                        // Check for removed values
                        for (const auto& pair : regValues) {
                            if (newValues.find(pair.first) == newValues.end()) {
                                logger->logEvent("REGISTRY", "Removed: " + pair.first +
                                               " (was '" + pair.second + "')", true);
                            }
                        }

                        regValues = newValues;
                    }
                }
            }
            RegCloseKey(hKey);
            CloseHandle(hEvent);
        }
        return 0;
    }

    HANDLE threads[3];

public:
    SystemLogger(const std::string& logFilePath) : logPath(logFilePath), running(false) {
        logFile.open(logPath, std::ios::app);
        if (!logFile.is_open()) {
            throw std::runtime_error("Failed to open log file");
        }
        logEvent("SYSTEM", "Logger started");
    }

    ~SystemLogger() {
        stop();
        logEvent("SYSTEM", "Logger stopped");
        logFile.close();
    }

    void startMonitoring() {
        running = true;
        logEvent("SYSTEM", "Starting system monitoring");

        threads[0] = CreateThread(NULL, 0, fileSystemMonitorThread, this, 0, NULL);
        threads[1] = CreateThread(NULL, 0, processMonitorThread, this, 0, NULL);
        threads[2] = CreateThread(NULL, 0, registryMonitorThread, this, 0, NULL);

        logEvent("SYSTEM", "All monitoring systems initialized");
    }

    void stop() {
        if (running) {
            running = false;
            WaitForMultipleObjects(3, threads, TRUE, 5000);
            for (int i = 0; i < 3; i++) {
                if (threads[i]) {
                    CloseHandle(threads[i]);
                    threads[i] = NULL;
                }
            }
        }
    }
};

int main() {
    try {
        std::string logPath = "system_log.txt";
        SystemLogger logger(logPath);

        logger.startMonitoring();

        std::cout << "Logger is running. Press Enter to stop..." << std::endl;
        std::cin.get();

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
