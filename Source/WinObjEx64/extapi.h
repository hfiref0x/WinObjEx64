/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2026
*
*  TITLE:       EXTAPI.H
*
*  VERSION:     2.10
*
*  DATE:        10 Feb 2026
*
*  Header for pre Windows 10+ missing API.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef NTSTATUS (NTAPI *pfnNtOpenPartition)(
    _Out_ PHANDLE PartitionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef NTSTATUS (NTAPI *pfnNtManagePartition)(
    _In_ HANDLE TargetHandle,
    _In_opt_ HANDLE SourceHandle,
    _In_ MEMORY_PARTITION_INFORMATION_CLASS PartitionInformationClass,
    _In_ PVOID PartitionInformation,
    _In_ ULONG PartitionInformationLength
    );

typedef NTSTATUS (NTAPI *pfnNtOpenRegistryTransaction)(
    _Out_ PHANDLE RegistryHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

typedef BOOL (WINAPI *pfnIsImmersiveProcess)(
    HANDLE hProcess
    );

typedef DPI_AWARENESS_CONTEXT (WINAPI *pfnGetThreadDpiAwarenessContext)(
    VOID);

typedef DPI_AWARENESS (WINAPI *pfnGetAwarenessFromDpiAwarenessContext)(
    _In_ DPI_AWARENESS_CONTEXT value);

typedef UINT (WINAPI *pfnGetDpiForWindow)(
    _In_ HWND hwnd);

typedef UINT (WINAPI *pfnGetDpiForSystem)(
    VOID);

//
// Only actual number of functions included in the EXTENDED_API_SET structure.
//
#define EXTAPI_ALL_MAPPED 7

typedef struct _EXTENDED_API_SET {
    ULONG NumberOfAPI;
    pfnNtOpenPartition NtOpenPartition;
    pfnNtOpenRegistryTransaction NtOpenRegistryTransaction;
    pfnIsImmersiveProcess IsImmersiveProcess;
    pfnGetThreadDpiAwarenessContext GetThreadDpiAwarenessContext;
    pfnGetAwarenessFromDpiAwarenessContext GetAwarenessFromDpiAwarenessContext;
    pfnGetDpiForWindow GetDpiForWindow;
    pfnGetDpiForSystem GetDpiForSystem;
} EXTENDED_API_SET, *PEXTENDED_API_SET;

NTSTATUS ExApiSetInit(
    VOID
    );

extern EXTENDED_API_SET g_ExtApiSet;

