# RpcProxyInvoke

### Overview

To create a general way to execute local and remote code, we designed a relatively obscure method of code execution, which we internally refer to as RpcCraft (Self) and RpcExec (Remote Process). This technique leverages a methodology well-known among exploit developers, abusing RPC (Remote Procedure Call) server calls such as `NdrServerCall2` or `NdrServerCallAll` to execute arbitrary code.

### Abusing Server Calls for Execution

Within `RPCRT4.dll`, functions like `NdrServerCall2`, `NdrServerCallAll`, and `NdrServerCallNdr64` (an alias of `NdrServerCallAll`) are implemented as wrappers to dynamically invoke functions pertaining to server functionalities. These functions take a single argument, a pointer to an `RPC_MESSAGE` structure.

**RPC_MESSAGE Structure:**
```c
typedef struct _RPC_MESSAGE {
  RPC_BINDING_HANDLE     Handle;
  unsigned long          DataRepresentation;
  void                   *Buffer;
  unsigned int           BufferLength;
  unsigned int           ProcNum;
  PRPC_SYNTAX_IDENTIFIER TransferSyntax;
  void                   *RpcInterfaceInformation;
  void                   *ReservedForRuntime;
  RPC_MGR_EPV            *ManagerEpv;
  void                   *ImportContext;
  unsigned long          RpcFlags;
} RPC_MESSAGE, *PRPC_MESSAGE;
```

### Initialization and Execution

To initialize the runtime without binding to a service, the `PerformRpcInitialization` function is used. This function internally initializes necessary structures without requiring manual binding.

### Known Issues

This public version of the technique has been developed as POC to showcase the feasibility, and it currently generates an exception on NdrGetBuffer due to a missing Binding Handle. This can be dealt with in several ways, but the current implementation does:

* Performs a patch to ntdll (RaiseException -> RtlExitUserThread)
* Recovers return value via VEH

```c
int FetchReturnValue(const PEXCEPTION_POINTERS ExceptionInfo) {
    ExceptionInfo->ContextRecord->EFlags |= (1 << 16);
    g_ReturnValue = (PVOID)ExceptionInfo->ContextRecord->Rax;
    return EXCEPTION_CONTINUE_EXECUTION;
}
```

### Limitations and Patching

RPC invocation is CFG protected, meaning that in order to achieve full, unrestricted code execution, it is necessary to either mark the target valid with `SetProcessValidCallTargets` or patching `RpcInvokeCheckICall`.

## Conclusion

The RpcProxyInvoke project demonstrates an alternate technique that can be abused to implement a RailGun style library. Although the public implementation is not perfect, it can serve as a basis for further development.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
