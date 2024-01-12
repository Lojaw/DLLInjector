#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string.h>

#include <locale>
#include <codecvt>

std::wstring string_to_wstring(const std::string& str) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.from_bytes(str);
}

DWORD FindProcessId(const std::wstring& processName) {
    DWORD processId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnap, &pe32)) {
            do {
                // Konvertieren Sie den WCHAR-Array zu einem std::wstring für den Vergleich
                std::wstring exeName(pe32.szExeFile);
                if (processName == exeName) {
                    processId = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pe32));
        }
        CloseHandle(hSnap);
    }
    return processId;
}

BOOL InjectDLL(const DWORD& processId, const std::string& dllPath) {
    // Öffnen Sie eine Handle zum Zielprozess mit genügend Rechten.
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) {
        std::cerr << "OpenProcess failed: " << GetLastError() << std::endl;
        return FALSE;
    }

    // Reservieren Sie Speicher im Zielprozess für den DLL-Pfad.
    LPVOID pDllPath = VirtualAllocEx(hProcess, 0, dllPath.size() + 1,
        MEM_COMMIT, PAGE_READWRITE);
    if (pDllPath == NULL) {
        std::cerr << "VirtualAllocEx failed: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return FALSE;
    }

    // Schreiben Sie den DLL-Pfad in den reservierten Speicher.
    BOOL wrote = WriteProcessMemory(hProcess, pDllPath,
        dllPath.c_str(), dllPath.size() + 1, 0);
    if (!wrote) {
        std::cerr << "WriteProcessMemory failed: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Erhalten Sie die Adresse der LoadLibrary-Funktion.
    LPVOID pLoadLibrary = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    if (pLoadLibrary == NULL) {
        std::cerr << "GetProcAddress failed: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Erstellen Sie einen Remote-Thread im Zielprozess, der LoadLibrary aufruft.
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibrary,
        pDllPath, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "CreateRemoteThread failed: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Warten Sie auf den Remote-Thread, um zu beenden.
    WaitForSingleObject(hThread, INFINITE);

    // Aufräumen
    VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    std::cerr << "Injection success!";
    return TRUE;
}


int main() {
    std::string targetProcess = "javaw.exe";
    std::string dllToInject = "C:\\Users\\jpsch\\Desktop\\C++\\OpenGLHookDLL\\x64\\Debug\\OpenGLHookDLL.dll";

    while (true) {
        DWORD processId = FindProcessId(string_to_wstring(targetProcess));
        if (processId != 0) {
            InjectDLL(processId, dllToInject);
            break; // Stoppen Sie die Schleife, wenn die Injektion erfolgreich war
        }
        // Warten Sie eine Weile, bevor Sie erneut überprüfen
        Sleep(3000);
    }

    return 0;
}