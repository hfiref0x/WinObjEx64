/************************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2023
*
*  TITLE:       NTLDR.H
*
*  VERSION:     1.22
*
*  DATE:        25 Jul 2023
*
*  Common header file for the NTLDR definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
************************************************************************************/

#if defined (_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#ifndef NTLDR_RTL
#define NTLDR_RTL

#pragma warning(push)
#pragma warning(disable: 4201) // nameless struct/union

#include <Windows.h>

#pragma warning(push)
#pragma warning(disable: 4005) //macro redefinition
#include <ntstatus.h>
#pragma warning(pop)

#include "ntos.h"
#include "apisetx.h"
#include "minirtl/minirtl.h"
#include "minirtl/rtltypes.h"

typedef INT(*PFNNTLDR_EXCEPT_FILTER)(
    _In_ UINT ExceptionCode,
    _In_ EXCEPTION_POINTERS* ExceptionPointers);

extern PFNNTLDR_EXCEPT_FILTER NtpLdrExceptionFilter;

//
// 
//  W32pServiceTable query related structures and definitions.
//
//

typedef enum _RESOLVE_POINTER_TYPE {
    ForwarderString = 0,
    FunctionCode = 1
} RESOLVE_POINTER_TYPE;

typedef struct _RESOLVE_INFO {
    RESOLVE_POINTER_TYPE ResultType;
    union {
        LPCSTR ForwarderName;
        LPVOID Function;
    };
} RESOLVE_INFO, *PRESOLVE_INFO;

typedef struct _RAW_SYSCALL_ENTRY {
    ULONG Index;
    CHAR Name[256];
    ULONG_PTR KernelStubAddress;
    ULONG_PTR KernelStubTargetAddress;
    struct _RAW_SYSCALL_ENTRY* NextEntry;
} RAW_SYSCALL_ENTRY, *PRAW_SYSCALL_ENTRY;

_Success_(return != NULL)
LPCSTR NtRawIATEntryToImport(
    _In_ LPVOID Module,
    _In_ LPVOID IATEntry,
    _Out_opt_ LPCSTR *ImportModuleName);

_Success_(return != 0)
ULONG NtRawEnumSyscallExports(
    _In_ HANDLE HeapHandle,
    _In_ LPVOID Module,
    _Out_ PRAW_SYSCALL_ENTRY* SyscallTable);

NTSTATUS NtRawGetProcAddress(
    _In_ LPVOID Module,
    _In_ LPCSTR ProcName,
    _In_ PRESOLVE_INFO Pointer);

NTSTATUS NtRawApiSetResolveLibrary(
    _In_ PVOID Namespace,
    _In_ PCUNICODE_STRING ApiSetToResolve,
    _In_opt_ PCUNICODE_STRING ApiSetParentName,
    _Inout_ PUNICODE_STRING ResolvedHostLibraryName);


#pragma warning(pop)

#endif NTLDR_RTL
