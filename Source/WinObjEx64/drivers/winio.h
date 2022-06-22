/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       WINIO.H
*
*  VERSION:     2.00
*
*  DATE:        19 Jun 2022
*
*  Common header file for the WINIO Driver Helper support.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define FILE_DEVICE_ASUSIO      (DWORD)0x0000A040

#define ASUSIO_MAP_FUNCID      (DWORD)0x920
#define ASUSIO_UNMAP_FUNCID    (DWORD)0x914

#define IOCTL_ASUSIO_MAP_USER_PHYSICAL_MEMORY    \
    CTL_CODE(FILE_DEVICE_ASUSIO, ASUSIO_MAP_FUNCID, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_ASUSIO_UNMAP_USER_PHYSICAL_MEMORY  \
    CTL_CODE(FILE_DEVICE_ASUSIO, ASUSIO_UNMAP_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define WINIO_IOCTL_MAP   IOCTL_ASUSIO_MAP_USER_PHYSICAL_MEMORY
#define WINIO_IOCTL_UNMAP IOCTL_ASUSIO_UNMAP_USER_PHYSICAL_MEMORY
#define WINIO_DRV_NAME L"Asusgio2"
#define WINIO_DEV_NAME L"Asusgio2"


typedef struct _WINIO_PHYSICAL_MEMORY_INFO {
    ULONG_PTR ViewSize;
    ULONG_PTR BusAddress; //physical address
    HANDLE SectionHandle;
    PVOID BaseAddress;
    PVOID ReferencedObject;
} WINIO_PHYSICAL_MEMORY_INFO, * PWINIO_PHYSICAL_MEMORYINFO;

typedef struct _WINIO_PHYSICAL_MEMORY_INFO_EX {
    ULONG_PTR CommitSize;
    ULONG_PTR BusAddress;
    HANDLE SectionHandle;
    PVOID BaseAddress;
    PVOID ReferencedObject;
    UCHAR EncryptedKey[16];
} WINIO_PHYSICAL_MEMORY_INFO_EX, * PWINIO_PHYSICAL_MEMORY_INFO_EX;

BOOL WinIoReadSystemMemory(
    _In_ WDRV_CONTEXT* Context,
    _In_ ULONG_PTR Address,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG NumberOfBytesRead);
