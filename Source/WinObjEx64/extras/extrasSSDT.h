/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2021
*
*  TITLE:       EXTRASSSDT.H
*
*  VERSION:     1.88
*
*  DATE:        10 Jan 2021
*
*  Common header file for Service Table dialog.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define INVALID_SERVICE_ENTRY_ID 0xFFFFFFFF
#define WIN32K_START_INDEX 0x1000

typedef struct _SERVICETABLEENTRY {
    ULONG ServiceId;
    ULONG_PTR Address;
    WCHAR Name[MAX_PATH + 1];
} SERVICETABLEENTRY, *PSERVICETABLEENTRY;

typedef struct _SDT_TABLE {
    BOOL Allocated;
    ULONG Limit;
    ULONG_PTR Base;
    PSERVICETABLEENTRY Table;
} SDT_TABLE, *PSDT_TABLE;

typedef enum _SSDT_DLG_MODE {
    SST_Ntos = 0,
    SST_Win32k = 1,
    SST_Max
} SSDT_DLG_MODE;

typedef struct _W32K_API_SET_TABLE_HOST {
    PWCHAR HostName;
    PCHAR TableName;
    PCHAR TableSizeName;
    ULONG HostEntriesCount;
} W32K_API_SET_TABLE_HOST, *PW32K_API_SET_TABLE_HOST;

typedef struct _W32K_API_SET_TABLE_ENTRY {
    PVOID HostEntriesArray;
    W32K_API_SET_TABLE_HOST* Host;
} W32K_API_SET_TABLE_ENTRY, * PW32K_API_SET_TABLE_ENTRY;

typedef struct _W32K_API_SET_TABLE_ENTRY_V2 {
    PVOID HostEntriesArray;
    W32K_API_SET_TABLE_HOST *Host;
    W32K_API_SET_TABLE_HOST *AliasHost;
} W32K_API_SET_TABLE_ENTRY_V2, *PW32K_API_SET_TABLE_ENTRY_V2;

VOID SdtFreeGlobals();

VOID extrasCreateSSDTDialog(
    _In_ HWND hwndParent,
    _In_ SSDT_DLG_MODE Mode);
