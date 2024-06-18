#pragma once
#include <windows.h>
#include <stdio.h>

DWORD CreateDetachedProcess(const wchar_t* lpCommandLine);
DWORD GetProcessIdByName(const wchar_t* processName);