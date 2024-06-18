#pragma once
#include <stdio.h>
#include <windows.h>
#include <stdint.h>

#define HEAP_SIZE 0x10000 // Define the size of the heap (64 KB)
#define MAX_ALLOCATIONS 256 // Maximum number of allocations to track

#define PACK( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop))

typedef struct {
    void* address;
    size_t size;
} AllocationRecord;

typedef struct {
    HANDLE hProcess;
    void* base;
    size_t allocated;
    size_t maxSize;
    AllocationRecord allocations[MAX_ALLOCATIONS];
    size_t allocationCount;
} HeapManager;


__pragma(pack(push, 1))
typedef struct _ARGUMENTS {
    BYTE pad0[6];
    UINT64 arg1;
    UINT64 arg2;
    UINT64 arg3;
    UINT64 arg4;
    UINT64 arg5;
    UINT64 arg6;
    UINT64 arg7;
    UINT64 arg8;
    UINT64 arg9;
    UINT64 arg10;
    UINT64 arg11;
    UINT64 arg12;
    UINT64 arg13;
} ARGUMENTS, * PARGUMENTS;
__pragma(pack(pop))

HeapManager g_heapManager = { 0 };

void InitializeHeapManager(HANDLE hProcess) {
    if (g_heapManager.base != NULL) {
        printf("Heap manager already initialized\n");
        return;
    }
    g_heapManager.base = VirtualAllocEx(hProcess, NULL, HEAP_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (g_heapManager.base == NULL) {
        printf("Failed to allocate heap\n");
        exit(1);
    }
    g_heapManager.maxSize = HEAP_SIZE;
    g_heapManager.hProcess = hProcess;
    g_heapManager.allocated = 0;
    g_heapManager.allocationCount = 0;
}

void* HeapManagerAlloc(size_t size) {
    if (g_heapManager.allocated + size > HEAP_SIZE) {
        printf("Out of memory\n");
        return NULL;
    }
    if (g_heapManager.allocationCount >= MAX_ALLOCATIONS) {
        printf("Maximum number of allocations reached\n");
        return NULL;
    }

    void* allocAddress = (uint8_t*)g_heapManager.base + g_heapManager.allocated;
    size_t roundedSize = (size + 0x255) & ~0x255;
    g_heapManager.allocated += roundedSize;

    g_heapManager.allocations[g_heapManager.allocationCount].address = allocAddress;
    g_heapManager.allocations[g_heapManager.allocationCount].size = roundedSize;
    g_heapManager.allocationCount++;

    return allocAddress;
}

void HeapManagerFree(HANDLE hProcess) {
    if (g_heapManager.base != NULL) {
        VirtualFreeEx(hProcess, g_heapManager.base, 0, MEM_RELEASE);
        g_heapManager.base = NULL;
        g_heapManager.allocated = 0;
        g_heapManager.allocationCount = 0;
    }
}

BOOL HeapManagerCopy(void* dst, void* src, size_t size) {
    SIZE_T bytesWritten;
    // Ensure that the destination address is within one of the allocations in the heap
    SIZE_T maxWriteableSize = 0;
    for (size_t i = 0; i < g_heapManager.allocationCount; i++) {
		if (dst >= g_heapManager.allocations[i].address && dst < (uint8_t*)g_heapManager.allocations[i].address + g_heapManager.allocations[i].size) {
			maxWriteableSize = (uint8_t*)g_heapManager.allocations[i].address + g_heapManager.allocations[i].size - (uint8_t*)dst;
            break;
		}
	}
	if (size > maxWriteableSize) {
		printf("Destination address is not within a valid allocation or size exceeds maximum writeable\n");
		return FALSE;
	}
	// Locate the chunk where the destination address is located
    return WriteProcessMemory(g_heapManager.hProcess, dst, src, size, &bytesWritten);
}

BOOL HeapManagerWriteDWORD(void* dst, DWORD value) {
	return HeapManagerCopy(dst, &value, sizeof(DWORD));
}

BOOL HeapManagerWriteWORD(void* dst, WORD value) {
	return HeapManagerCopy(dst, &value, sizeof(WORD));
}

BOOL HeapManagerWriteBYTE(void* dst, BYTE value) {
	return HeapManagerCopy(dst, &value, sizeof(BYTE));
}

BOOL HeapManagerWriteQWORD(void* dst, uint64_t value) {
	return HeapManagerCopy(dst, &value, sizeof(uint64_t));
}
