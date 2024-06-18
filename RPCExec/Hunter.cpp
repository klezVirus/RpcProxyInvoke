#include "Hunter.h"

PVOID HuntForCopInstruction(PVOID startAddress, SIZE_T size) {
    UINT64 currentAddress = (UINT64)startAddress;
    UINT64 endAddress = currentAddress + size;

    while (currentAddress < endAddress) {
        if (*(DWORD*)currentAddress == 0x48d2ff41) {
            return (PVOID)currentAddress;
        }

        currentAddress++;
    }

    return NULL;
}


PVOID HuntForCall(PVOID startAddress, SIZE_T size, BOOL backword) {
    UINT64 currentAddress = (UINT64)startAddress;
    UINT64 endAddress = currentAddress + size;
    if (backword) {
		currentAddress = currentAddress - size;
		endAddress = (UINT64)startAddress;
    }

    while (currentAddress < endAddress) {
        if (*(BYTE*)currentAddress == 0xe8 && 0xffff0000  <= *(DWORD*)(currentAddress+1) && *(DWORD*)(currentAddress + 1) <= 0xfffffff0) {
            return (PVOID)currentAddress;
        }
        currentAddress++;
    }
    return NULL;
}

UINT64 CalculateCallTarget(HMODULE hMod, UINT64 callAddress) {
	DWORD offset = *(DWORD*)(callAddress + 1) + 5;
	DWORD relativeCallAddress = (DWORD)(callAddress - (UINT64)hMod);
    
    DWORD targetRva = (relativeCallAddress + offset) & 0xffffffff;
	return (UINT64)hMod + targetRva;
}