/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023 - 2024
*
*  TITLE:       W32K.H
*
*  VERSION:     2.05
*
*  DATE:        11 May 2024
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

//
// It is overcomplicated since we have to support multiple variants of what
// MS did to win32k shadow table handling since REDSTONE1.
// 
// 1. Win32k table data change (X2)
// 2. Win32k table entries forwarding
// 3. Win32k ApiSetTable
// 4. Win32k ApiSetTable improvement
// 5. Win32k session aware ApiSets
// 6. Win32kSgd merge into win32k.sys
//

//
// The following structure only valid for deprecated win32ksgd.
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
} SGD_GLOBALS, *PSGD_GLOBALS;

typedef struct _W32K_GLOBALS {
    PVOID gLowSessionGlobalSlots;  //pointer to list
    ULONG gAvailableSlots;
    ULONG Reserved0;
    PVOID gSessionGlobalSlots;     //pointer to list
    PVOID gpSESSIONSLOTS;          //pointer to list
    LIST_ENTRY gSessionSlotsList;  //gpSESSIONSLOTS is the head
    struct {
        ULONG LowCount;
        ULONG HighCount;
        ULONGLONG TotalCount;
    } gSessionApiSetHostRefCount;
    PVOID gSessionApiSetHostRefCountLock;
    PVOID gSessionProcessLifetimeLock; //W32_PUSH_LOCK
    PVOID gLock; //W32_PUSH_LOCK
} W32K_GLOBALS, *PW32K_GLOBALS;

//
//  ApiSet layout 24H2
//
//  WIN32K!gSessionGlobalSlots:
//
//  +------+
//  | Slot |
//  +------+------+------------+
//  |  0   |  ... |  MaxSlot   |
//  +------+------+------------+
//
//  where
//
//      MaxSlot - is the maximum allocated slot
//
//  slot selection scheme 
//
//      Current process SessionId - 1, i.e. 0 for SessionId 1
// 
// Each slot is a pointer to tagWIN32KSESSIONSTATE opaque structure which
// holds multiple global variables for given session, 
// including Win32kApiSetTable pointer (at +0x88 for 26212 24H2).
// 
// If current session id is zero then apiset will be resolved from 
// WIN32K!gLowSessionGlobalSlots instead.
// 
// Win32kApiSetTable layout is the same as pre Win11.
// 
// Array of host entries each contains another array of apiset table entries.
//
//   See W32K_API_SET_TABLE_ENTRY_V2. 
// 
// The difference between current implementation and what was in win10 pre 24H2
// is that ApiSet data moved to the kernel memory and apisets are now session aware
// which now allows them:
//   1. Further services (session 0) isolation to reduce possible attack surfaces.
//   2. Stop leaking kernel addresses through manual resolve in user mode.
//
// To walk 24H2 table you have to find the following offsets in the kernel table 
// for given entry inside win32k:
// 
//      1. Offset to ApiSet host structure pointer
//      2. Offset in the ApiSet host enties array
//
// Globally you must also find offset to apiset table pointer in tagWIN32KSESSIONSTATE 
// as it can be subject of change.
// 
//

typedef struct _SDT_CONTEXT {
    BOOL Initialized;
    BOOL ApiSetSessionAware;

    ULONG_PTR KernelBaseAddress;            //win32k.sys kernel image base address
    ULONG_PTR KernelImageSize;              //win32k.sys kernel image size

    HANDLE ExportsEnumHeap;                 //heap handle for enum

    HMODULE UserModule;                     //win32u.dll hmodule
    HMODULE KernelModule;                   //win32k.sys hmodule

    PRAW_SYSCALL_ENTRY UserTable;           //win32u syscalls exports dump
    ULONG UserLimit;                        //win32u syscalls count
    ULONG KernelLimit;                      //win32k syscalls count

    ULONG SessionId;                        //current session id
    ULONG Win32kApiSetTableOffset;          //SGD offset to Win32kApiSetTable

    ULONG_PTR Win32kApiSetTable;            //Win32kApiSetTable user address for pre-24H2
    ULONG_PTR W32GetSessionStatePtr;        //Function pointer

    ULONG_PTR W32pServiceTableKernelBase;   //W32pServiceTable calculated kernel address
    PULONG W32pServiceTableUserBase;        //W32pServiceTable user address
    W32K_GLOBALS W32Globals;                //win32k.sys global variables
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
