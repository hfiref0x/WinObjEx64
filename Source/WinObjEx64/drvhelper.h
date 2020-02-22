/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       DRVHELPER.H
*
*  VERSION:     1.84
*
*  DATE:        14 Feb 2019
*
*  Common header file for the Kernel Driver Helper support.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define FILE_DEVICE_WINIO       (DWORD)0x00008010

#define WINIO_IOCTL_INDEX       (DWORD)0x810

#define WINIO_MAP_FUNCID        (DWORD)WINIO_IOCTL_INDEX
#define WINIO_UNMAP_FUNCID      (DWORD)WINIO_IOCTL_INDEX + 1

#define IOCTL_WINIO_MAP_USER_PHYSICAL_MEMORY     \
    CTL_CODE(FILE_DEVICE_WINIO, WINIO_MAP_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_WINIO_UNMAP_USER_PHYSICAL_MEMORY   \
    CTL_CODE(FILE_DEVICE_WINIO, WINIO_UNMAP_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _WINIO_PHYSICAL_MEMORY_INFO_EX {
    ULONG_PTR CommitSize;
    ULONG_PTR BusAddress;
    HANDLE SectionHandle;
    PVOID BaseAddress;
    PVOID ReferencedObject;
    UCHAR EncryptedKey[16];
} WINIO_PHYSICAL_MEMORY_INFO_EX, * PWINIO_PHYSICAL_MEMORY_INFO_EX;

//
// Prototype for read physical memory function.
//
typedef NTSTATUS(WINAPI* provReadPhysicalMemory)(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

//
// Prototype for query PML4 value function.
//
typedef NTSTATUS(WINAPI* provQueryPML4)(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value);

BOOL WinIoReadSystemMemoryEx(
    _In_ ULONG_PTR Address,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG NumberOfBytesRead);
