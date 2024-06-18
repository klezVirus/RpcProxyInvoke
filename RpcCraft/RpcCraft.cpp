#include <stdio.h>
#include <windows.h>
#include <rpcdce.h>
#include <rpcndr.h>
#include <intrin.h>
#include "hexutls.h"
#include "RpcExec.h"

#pragma comment(lib, "rpcrt4.lib")

// OFFSETS relative to Windows 11 24H
#define RPC_INIT_OFFSET 0x759c
#define RPC_INVOKE_OFFSET 0x677f0


void write_data_to_address(
    void* data,
    size_t data_size,
    void* address
) {
    memcpy(address, data, data_size);
}

static const unsigned short MyInterface_FormatStringOffsetTable[] =
{
0
};

PVOID HuntForCopInstruction(PVOID startAddress, SIZE_T size) {
    UINT64 currentAddress = (UINT64)startAddress;
    UINT64 endAddress = currentAddress + size;

    while (currentAddress < endAddress) {
        if (*(DWORD*)currentAddress == 0x48d2ff41) {
            return (PVOID)currentAddress;
        }
        // printf("0x%llx: %02x\n", currentAddress, *(unsigned char*)currentAddress);

        currentAddress++;
    }

    return NULL;
}

void craft_rpc_message(
    void* arguments_address,
    void* function_address
) {
    RPC_MESSAGE* rpc_message = (RPC_MESSAGE*)VirtualAlloc(NULL, sizeof(RPC_MESSAGE), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    RPC_DISPATCH_TABLE* rpc_dispatch_table = (RPC_DISPATCH_TABLE*)VirtualAlloc(NULL, sizeof(RPC_DISPATCH_TABLE), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    MIDL_STUB_DESC* midl_stub_desc = (MIDL_STUB_DESC*)VirtualAlloc(NULL, sizeof(MIDL_STUB_DESC), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    MIDL_SERVER_INFO* midl_server_info = (MIDL_SERVER_INFO*)VirtualAlloc(NULL, sizeof(MIDL_SERVER_INFO), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    RPC_CLIENT_INTERFACE* rpc_client_interface = (RPC_CLIENT_INTERFACE*)VirtualAlloc(NULL, sizeof(RPC_CLIENT_INTERFACE), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    RPC_SYNTAX_IDENTIFIER* rpc_syntax_identifier = (RPC_SYNTAX_IDENTIFIER*)VirtualAlloc(NULL, sizeof(RPC_SYNTAX_IDENTIFIER), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    RPC_VERSION* rpc_version = (RPC_VERSION*)VirtualAlloc(NULL, sizeof(RPC_VERSION), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    BYTE* proc_string = (BYTE*)VirtualAlloc(NULL, 200, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); 
        
    BYTE stack_string[] = {
            0x32, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x00, 0xc0, 0x00, 0x10, 0x00, 0x44,
            0x0d, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00,
            0x0b, 0x00, 0x48, 0x00, 0x08, 0x00, 0x0b, 0x00, 0x48, 0x00, 0x10, 0x00, 0x0b, 0x00, 0x48,
            0x00, 0x18, 0x00, 0x0b, 0x00, 0x48, 0x00, 0x20, 0x00, 0x0b, 0x00, 0x48, 0x00, 0x28, 0x00,
            0x0b, 0x00, 0x48, 0x00, 0x30, 0x00, 0x0b, 0x00, 0x48, 0x00, 0x38, 0x00, 0x0b, 0x00, 0x48,
            0x00, 0x40, 0x00, 0x0b, 0x00, 0x48, 0x00, 0x48, 0x00, 0x0b, 0x00, 0x48, 0x00, 0x50, 0x00,
            0x0b, 0x00, 0x48, 0x00, 0x58, 0x00, 0x0b, 0x00, 0x70, 0x00, 0x60, 0x00, 0x0b, 0x00, 0x00,
    };

    // Check all for null
	if (rpc_message == NULL || rpc_dispatch_table == NULL || midl_stub_desc == NULL || midl_server_info == NULL || rpc_client_interface == NULL || rpc_syntax_identifier == NULL || rpc_version == NULL || proc_string == NULL) {
		printf("Failed to allocate memory for RPC Message\n");
		return;
	}

	// Print all addresses and the var name
	printf("rpc_message: %p\n", rpc_message);
	printf("rpc_dispatch_table: %p\n", rpc_dispatch_table);
	printf("midl_stub_desc: %p\n", midl_stub_desc);
	printf("midl_server_info: %p\n", midl_server_info);
	printf("rpc_client_interface: %p\n", rpc_client_interface);
	printf("rpc_syntax_identifier: %p\n", rpc_syntax_identifier);
	printf("rpc_version: %p\n", rpc_version);
	printf("proc_string: %p\n", proc_string);

    memset(rpc_message, 0, sizeof(RPC_MESSAGE));
    memset(rpc_dispatch_table, 0, sizeof(RPC_DISPATCH_TABLE));
    memset(midl_stub_desc, 0, sizeof(MIDL_STUB_DESC));
    memset(midl_server_info, 0, sizeof(MIDL_SERVER_INFO));
    memset(rpc_client_interface, 0, sizeof(RPC_CLIENT_INTERFACE));
    memset(rpc_syntax_identifier, 0, sizeof(RPC_SYNTAX_IDENTIFIER));
    memset(rpc_version, 0, sizeof(RPC_VERSION));
    memset(proc_string, 0, 200);

	memcpy(proc_string, stack_string, sizeof(stack_string));

    rpc_dispatch_table->DispatchTableCount = 1;
    rpc_dispatch_table->DispatchTable = (RPC_DISPATCH_FUNCTION*)function_address;

    rpc_version->MajorVersion = 2;
    rpc_syntax_identifier->SyntaxVersion = *rpc_version;

    midl_stub_desc->Version = 0x50002;
    midl_stub_desc->MIDLVersion = 0x800025b;
    midl_stub_desc->mFlags = 1;
    midl_stub_desc->fCheckBounds = 1;
    midl_stub_desc->RpcInterfaceInformation = rpc_client_interface;
    midl_stub_desc->pfnAllocate = malloc;
    midl_stub_desc->pfnFree = free;

    midl_server_info->pStubDesc = midl_stub_desc;
    midl_server_info->DispatchTable = (SERVER_ROUTINE*)rpc_dispatch_table->DispatchTable;
    midl_server_info->ProcString = (PFORMAT_STRING)proc_string;
    midl_server_info->FmtStringOffset = MyInterface_FormatStringOffsetTable;

    rpc_client_interface->Length = sizeof(RPC_CLIENT_INTERFACE);
    rpc_client_interface->InterfaceId.SyntaxVersion.MajorVersion = 1;
    rpc_client_interface->TransferSyntax.SyntaxVersion.MajorVersion = 2;
    rpc_client_interface->Flags = 0x4000000;
    rpc_client_interface->DispatchTable = rpc_dispatch_table;
    rpc_client_interface->InterpreterInfo = midl_server_info;

    rpc_message->Handle = NULL;
    rpc_message->RpcFlags = 0x1000;
    rpc_message->DataRepresentation = 0x10;
    rpc_message->RpcInterfaceInformation = rpc_client_interface;
    rpc_message->BufferLength = 14 * sizeof(void*);
    rpc_message->Buffer = arguments_address;

    __try {
        NdrServerCall2(rpc_message);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("Exception occurred\n");
    }

    VirtualFree(rpc_message, 0, MEM_RELEASE);
    VirtualFree(rpc_dispatch_table, 0, MEM_RELEASE);
    VirtualFree(midl_stub_desc, 0, MEM_RELEASE);
    VirtualFree(midl_server_info, 0, MEM_RELEASE);
    VirtualFree(rpc_client_interface, 0, MEM_RELEASE);
    VirtualFree(rpc_syntax_identifier, 0, MEM_RELEASE);
    VirtualFree(rpc_version, 0, MEM_RELEASE);
    VirtualFree(proc_string, 0, MEM_RELEASE);

}

int main() {
    PARGUMENTS arguments_address = (PARGUMENTS)malloc(sizeof(ARGUMENTS)); 
	if (arguments_address == NULL) {
		printf("Failed to allocate memory for arguments\n");
		return 1;
	}
    memset(arguments_address, 0, sizeof(ARGUMENTS));

	LPVOID title = HeapAlloc(GetProcessHeap(), 0, 0x100);
	LPVOID text = HeapAlloc(GetProcessHeap(), 0, 0x100);
	if (title == NULL || text == NULL) {
		printf("Failed to allocate memory for title and text\n");
		return 1;
	}

	memcpy(text, "Hello from RpcCraft", 20);
	memcpy(title, "RpcCraft", 9);

	arguments_address->arg1 = (PVOID)0;
	arguments_address->arg2 = (PVOID)text;
	arguments_address->arg3 = (PVOID)title;
	arguments_address->arg4 = (PVOID)0;

    HMODULE hMod = LoadLibraryA("kernelbase.dll");
    HMODULE hRpcRt4 = LoadLibraryA("rpcrt4.dll");
    HMODULE hU32 = LoadLibraryA("user32.dll");

    if (hMod == NULL || hRpcRt4 == NULL || hU32 == NULL)
    {
        printf("Failed to load DLLs\n");
        return 1;
    }

    FARPROC RpcInit = (FARPROC)GetProcAddress(hRpcRt4, "PerformRpcInitialization");
    if (RpcInit == NULL)
    {
        printf("Failed to get PerformRpcInitialization function address: %08x\n", GetLastError());
        RpcInit = (FARPROC)((UINT64)hRpcRt4 + RPC_INIT_OFFSET);
        printf("Using hardcoded offset address: 0x%llx\n", (ULONGLONG)RpcInit);
    }

    RpcInit();

    LPVOID rpcBindingHandle = (LPVOID)((UINT64)hRpcRt4 + (UINT64)0xd7778);


    /*
    HANDLE rpcHeap = HeapCreate(0, 0x1000, 0x4000);
    LPVOID rHeapBase = LPVOID((UINT64)hRpcRt4 + (DWORD)0xfff98);

    *((UINT64*)rHeapBase) = (UINT64)rpcHeap;

    LPVOID threadListMutex = LPVOID((UINT64)hRpcRt4 + (DWORD)0xfff50);
    LPVOID threadListHead = LPVOID((UINT64)hRpcRt4 + (DWORD)0x100130);

    CRITICAL_SECTION criticalSection = { 0 };
    InitializeCriticalSection(&criticalSection);

    *((UINT64*)threadListMutex) = (UINT64)&criticalSection;
    *((UINT64*)threadListHead) = (UINT64)threadListHead;
    *((UINT64*)threadListHead + 0x8) = (UINT64)threadListHead;
    */

    FARPROC targetFunction = GetProcAddress(hU32, "MessageBoxA");
    if (targetFunction == NULL)
    {
        printf("Failed to get MessageBoxA function address: %08x\n", GetLastError());
        return 1;
    }
    printf("Function `MessageBoxA` address: 0x%llx\n", (ULONGLONG)targetFunction);
    
	UINT64 invokeAddress = (UINT64)hRpcRt4 + RPC_INVOKE_OFFSET;

	PVOID hookAddress = HuntForCopInstruction((PVOID)invokeAddress, 0x1000);
	if (hookAddress == NULL) {
		printf("Failed to find COP instruction\n");
		return 1;
	}
	EngineStart((PVOID)((UINT64)hookAddress + 3));

	HookCallWith((PVOID)((UINT64)hookAddress + 3), (PVOID)FetchReturnValue, 0);


	for (int i = 0; i < 3; i++) {
        craft_rpc_message(arguments_address, &targetFunction);
		printf("Return Value: 0x%llx\n", (UINT64)g_ReturnValue);
    }

	EngineStop();

    free(arguments_address);

    return 0;
}
