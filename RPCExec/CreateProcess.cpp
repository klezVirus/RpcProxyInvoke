#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>

DWORD CreateDetachedProcess(const wchar_t* lpCommandLine) {
    STARTUPINFO* si;
    PPROCESS_INFORMATION pi;
    DWORD processId = 0;

    si = (STARTUPINFO*)malloc(sizeof(STARTUPINFO));
    pi = (PROCESS_INFORMATION*)malloc(sizeof(PROCESS_INFORMATION));
    if (si == NULL || pi == NULL) {
        wprintf(L"malloc failed\n");
        return -1;
    }
    ZeroMemory(si, sizeof(si));
    si->cb = sizeof(si);
    ZeroMemory(pi, sizeof(pi));

    // Start the child process.
    if (!CreateProcessW(
        NULL,                // No module name (use command line)
        (LPWSTR)lpCommandLine,       // Command line
        NULL,                // Process handle not inheritable
        NULL,                // Thread handle not inheritable
        FALSE,               // Set handle inheritance to FALSE
        DETACHED_PROCESS,    // Detached process creation flag
        NULL,                // Use parent's environment block
        NULL,                // Use parent's starting directory
        si,                  // Pointer to STARTUPINFO structure
        pi)                  // Pointer to PROCESS_INFORMATION structure
        ) {
        wprintf(L"CreateProcessW failed (%d).\n", GetLastError());
        return -1;
    }

    processId = pi->dwProcessId;
    // Close process and thread handles.
    CloseHandle(pi->hProcess);
    CloseHandle(pi->hThread);

    return processId;
}


// Find process by name
DWORD GetProcessIdByName(const wchar_t* processName) {
	DWORD pid = -1;
	PROCESSENTRY32 pe32;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return pid;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hSnapshot, &pe32)) {
		CloseHandle(hSnapshot);
		return pid;
	}
	do {
		if (wcscmp(pe32.szExeFile, processName) == 0) {
			pid = pe32.th32ProcessID;
			break;
		}
		// printf("Process: %ls\n", pe32.szExeFile);
	} while (Process32Next(hSnapshot, &pe32));
	CloseHandle(hSnapshot);
	return pid;
}