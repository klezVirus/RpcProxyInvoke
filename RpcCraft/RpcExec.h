#pragma once
#include "hwbp.h"

//////////////////////////////////////////////////////////////////////////////////////////
/*                                        Functions                                     */
//////////////////////////////////////////////////////////////////////////////////////////
PVOID       g_Handler = NULL;
PVOID       g_ReturnValue = NULL;

typedef struct _ARGUMENTS {
	PVOID arg1;
	PVOID arg2;
	PVOID arg3;
	PVOID arg4;
	PVOID arg5;
	PVOID arg6;
	PVOID arg7;
	PVOID arg8;
	PVOID arg9;
	PVOID arg10;
	PVOID arg11;
	PVOID arg12;
} ARGUMENTS, * PARGUMENTS;

VOID HookCallWith(PVOID fptr, PVOID callback, UINT pos)
{
    if (fptr == NULL) {
        return;
    }

    if (g_Handler == NULL) {
        return;
    }

    insert_descriptor_entry(fptr, pos, (exception_callback)callback, 0, TRUE);

}

VOID UnHookCall(PVOID fptr)
{
    if (fptr == NULL) {
        return;
    }

    if (g_Handler == NULL) {
        return;
    }

    delete_descriptor_entry(fptr, 0);

}

VOID EngineStart(PVOID fptr)
{
    g_Handler = hardware_engine_init();
}

VOID EngineStop() {
    hardware_engine_stop(g_Handler);
}

int FetchReturnValue(const PEXCEPTION_POINTERS ExceptionInfo)
{
    ExceptionInfo->ContextRecord->EFlags |= (1 << 16);
	g_ReturnValue = (PVOID)ExceptionInfo->ContextRecord->Rax;
    return EXCEPTION_CONTINUE_EXECUTION;
}

