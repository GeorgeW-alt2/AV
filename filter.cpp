#include <windows.h>
#include <iostream>
#include <cstdlib>

bool networkEnabled = true;

// Function to enable/disable network adapter
void toggleNetwork() {
    if (networkEnabled) {
        // Disable network adapter
        system("netsh interface set interface \"Ethernet\" admin=disable");
        system("netsh interface set interface \"Wi-Fi\" admin=disable");
        networkEnabled = false;
        std::cout << "Network disabled\n";
    } else {
        // Enable network adapter
        system("netsh interface set interface \"Ethernet\" admin=enable");
        system("netsh interface set interface \"Wi-Fi\" admin=enable");
        networkEnabled = true;
        std::cout << "Network enabled\n";
    }
}

// Windows procedure for handling keyboard input
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        if (wParam == WM_KEYDOWN) {
            KBDLLHOOKSTRUCT* kbStruct = (KBDLLHOOKSTRUCT*)lParam;
            // Check for F12 key
            if (kbStruct->vkCode == VK_F12) {
                toggleNetwork();
            }
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

int main() {
    std::cout << "Network Toggle Program\n";
    std::cout << "Press F12 to toggle network connection\n";
    std::cout << "Press Ctrl+C to exit\n\n";

    // Set up keyboard hook
    HHOOK keyboardHook = SetWindowsHookEx(
        WH_KEYBOARD_LL,
        KeyboardProc,
        GetModuleHandle(NULL),
        0
    );

    if (keyboardHook == NULL) {
        std::cout << "Failed to set up keyboard hook\n";
        return 1;
    }

    // Message loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // Clean up
    UnhookWindowsHookEx(keyboardHook);
    return 0;
}
