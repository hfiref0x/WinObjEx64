/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       EXTAPI.H
*
*  VERSION:     1.70
*
*  DATE:        30 Nov 2018
*
*  Windows/Native API which we cannot statically link because have to support Windows 7
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

typedef BOOL (WINAPI *pfnIsImmersiveProcess)(
    HANDLE hProcess
    );

typedef HWINSTA(NTAPI* pfnNtUserOpenWindowStation)(
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ACCESS_MASK DesiredAccess
    );

#define EXTAPI_ALL_MAPPED 3

typedef struct _EXTENDED_API_SET {
    ULONG NumberOfAPI;
    pfnNtOpenPartition NtOpenPartition;
    pfnNtUserOpenWindowStation NtUserOpenWindowStation;
    pfnIsImmersiveProcess IsImmersiveProcess;
} EXTENDED_API_SET, *PEXTENDED_API_SET;

NTSTATUS ExApiSetInit(
    VOID
    );

extern EXTENDED_API_SET g_ExtApiSet;

