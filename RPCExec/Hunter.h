#pragma once
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

PVOID HuntForCopInstruction(PVOID startAddress, SIZE_T size);
PVOID HuntForCall(PVOID startAddress, SIZE_T size, BOOL backword);
UINT64 CalculateCallTarget(HMODULE hMod, UINT64 callAddress);