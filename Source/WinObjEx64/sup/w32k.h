/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       W32K.H
*
*  VERSION:     2.03
*
*  DATE:        21 Jul 2023
*
*  Common header file for the win32k support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define WIN32K_FILENAME     L"win32k.sys"       // base kernel module
#define WIN32U_FILENAME     L"win32u.dll"       // base user module
#define WIN32KSGD_FILENAME  L"win32ksgd.sys"    // session global kernel module

//
// It is overcomplicated since we have to support multiple variants of what
// MS did to win32k shadow table handling since REDSTONE1.
// 
// 1. Win32k table data change (X2)
// 2. Win32k table entries forwarding
// 3. Win32k ApiSetTable
// 4. Win32k ApiSetTable improvement
// 5. Win32k session aware ApiSets
//
typedef struct _SGD_GLOBALS {
    PVOID gSessionGlobalSlots;     //pointer to list
    PVOID gpSESSIONSLOTS;          //pointer to list
    LIST_ENTRY gSessionSlotsList;  //gpSESSIONSLOTS is the head
    struct {
        ULONG LowCount;
        ULONG HighCount;
        ULONGLONG TotalCount;
    } gSessionApiSetHostRefCount;
    PVOID gSessionApiSetHostRefCountLock;
    PVOID gLowSessionGlobalSlots;  //pointer to list
    ULONG gAvailableSlots;
} SGD_GLOBALS, * PSGD_GLOBALS;

typedef struct _SDT_CONTEXT {
    BOOL Initialized;
    BOOL ApiSetSessionAware;

    ULONG_PTR KernelBaseAddress;            //win32k.sys kernel image base address
    ULONG_PTR KernelImageSize;              //win32k.sys kernel image size

    ULONG_PTR SgdBaseAddress;               //win32ksgd.sys kernel image base address
    ULONG_PTR SgdImageSize;                 //win32ksgd.sys kernel image size

    HANDLE ExportsEnumHeap;                 //heap handle for enum

    HMODULE UserModule;                     //win32u.dll hmodule
    HMODULE KernelModule;                   //win32k.sys hmodule
    HMODULE SgdModule;                      //win32ksgd.sys hmodule

    PRAW_SYSCALL_ENTRY UserTable;           //win32u syscalls exports dump
    ULONG UserLimit;                        //win32u syscalls count
    ULONG KernelLimit;                      //win32k syscalls count

    ULONG SessionId;                        //current session id
    ULONG Win32kApiSetTableOffset;          //SGD offset to Win32kApiSetTable

    ULONG_PTR Win32kApiSetTable;            //Win32kApiSetTable user address for pre-24H2

    ULONG_PTR W32pServiceTableKernelBase;   //W32pServiceTable calculated kernel address
    PULONG W32pServiceTableUserBase;        //W32pServiceTable user address
    SGD_GLOBALS SgdGlobals;                 //win32ksgd.sys global variables

} SDT_CONTEXT, * PSDT_CONTEXT;

typedef struct _SDT_FUNCTION_NAME {
    LPCSTR ServiceName;
    LPCSTR ExportName;
    USHORT ExportOrdinal;
} SDT_FUNCTION_NAME, * PSDT_FUNCTION_NAME;

typedef struct _SDT_MODULE_ENTRY {
    struct _SDT_MODULE_ENTRY* Next;
    DWORD Hash;
    HMODULE ImageBase;
    UNICODE_STRING Name;
} SDT_MODULE_ENTRY, * PSDT_MODULE_ENTRY;

NTSTATUS SdtResolveServiceEntryModule(
    _In_ PSDT_CONTEXT Context,
    _In_ PBYTE FunctionPtr,
    _In_ PSDT_MODULE_ENTRY ModulesHead,
    _Inout_ PSDT_MODULE_ENTRY ModuleEntry);

NTSTATUS SdtResolveServiceEntryModuleSessionAware(
    _In_ PSDT_CONTEXT Context,
    _In_ PBYTE FunctionPtr,
    _In_ PRTL_PROCESS_MODULES Modules,
    _Inout_ PSDT_FUNCTION_NAME ServiceName,
    _In_ PSDT_MODULE_ENTRY ModulesHead,
    _Inout_ PSDT_MODULE_ENTRY ModuleEntry);

ULONG SdtWin32kInitializeOnce(
    _In_ PRTL_PROCESS_MODULES pModules,
    _Inout_ PSDT_CONTEXT Context);

VOID SdtWin32kUninitialize(
    _In_ PSDT_CONTEXT Context);

NTSTATUS SdtLoadAndRememberModule(
    _In_ PSDT_MODULE_ENTRY Head,
    _In_ PUNICODE_STRING ModuleName,
    _Inout_ PSDT_MODULE_ENTRY Entry,
    _In_ BOOL ModuleNameAllocated);

VOID SdtUnloadRememberedModules(
    _In_ PSDT_MODULE_ENTRY Head);
