/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       EXTAPI.H
*
*  VERSION:     1.53
*
*  DATE:        07 Mar 2018
*
*  Header file for Windows 10 new API which we cannot statically link.
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
    _In_ HANDLE SourceHandle,
    _In_ MEMORY_PARTITION_INFORMATION_CLASS PartitionInformationClass,
    _Inout_ PVOID PartitionInformation,
    _In_ SIZE_T PartitionInformationLength
    );

typedef struct _EXTENDED_API_SET {
    pfnNtOpenPartition NtOpenPartition;
    pfnNtManagePartition NtManagePartition;
} EXTENDED_API_SET, *PEXTENDED_API_SET;

NTSTATUS ExApiSetInit(
    VOID
    );

extern EXTENDED_API_SET g_ExtApiSet;

