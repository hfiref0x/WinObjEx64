/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       EXTRASSSDTSUP.H
*
*  VERSION:     1.94
*
*  DATE:        04 Jun 2022
*
*  Header with search patterns and definitions used by SSDT dialog routines.
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
} SERVICETABLEENTRY, * PSERVICETABLEENTRY;

typedef struct _SDT_TABLE {
    BOOL Allocated;
    ULONG Limit;
    ULONG_PTR Base;
    PSERVICETABLEENTRY Table;
} SDT_TABLE, * PSDT_TABLE;

typedef struct _W32K_API_SET_TABLE_HOST {
    PWCHAR HostName;
    PCHAR TableName;
    PCHAR TableSizeName;
    ULONG HostEntriesCount;
} W32K_API_SET_TABLE_HOST, * PW32K_API_SET_TABLE_HOST;

typedef struct _W32K_API_SET_TABLE_ENTRY {
    PVOID HostEntriesArray;
    W32K_API_SET_TABLE_HOST* Host;
} W32K_API_SET_TABLE_ENTRY, * PW32K_API_SET_TABLE_ENTRY;

typedef struct _W32K_API_SET_TABLE_ENTRY_V2 {
    PVOID HostEntriesArray;
    W32K_API_SET_TABLE_HOST* Host;
    W32K_API_SET_TABLE_HOST* AliasHost;
} W32K_API_SET_TABLE_ENTRY_V2, * PW32K_API_SET_TABLE_ENTRY_V2;

#define KSW_KiServiceTable L"KiServiceTable"
#define KSW_KiServiceLimit L"KiServiceLimit"
#define KSW_W32pServiceTable L"W32pServiceTable"
#define KSW_W32pServiceLimit L"W32pServiceLimit"
#define KSA_W32pServiceTable "W32pServiceTable"
#define KSA_W32pServiceLimit "W32pServiceLimit"



//
// Win32kApiSetTable signatures
//

// lea reg, Win32kApiSetTable
#define IL_Win32kApiSetTable 7

//
// InitializeWin32Call search pattern
//
// push rbp
// push r12
// push r13
// push r14
// push r15
//
BYTE g_pbInitializeWin32CallPattern[] = {
    0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57
};

//
// Win32kApiSetTable adapter patterns
//
BYTE Win32kApiSetAdapterPattern1[] = {
   0x4C, 0x8B, 0x15
};
BYTE Win32kApiSetAdapterPattern2[] = {
   0x48, 0x8B, 0x05
};
BYTE Win32kApiSetAdapterPattern3[] = {
   0x4C, 0x8B, 0x1D // mov r11, value
};

W32K_API_SET_LOOKUP_PATTERN W32kApiSetAdapters[] = {
    { sizeof(Win32kApiSetAdapterPattern1), Win32kApiSetAdapterPattern1 },
    { sizeof(Win32kApiSetAdapterPattern2), Win32kApiSetAdapterPattern2 },
    { sizeof(Win32kApiSetAdapterPattern3), Win32kApiSetAdapterPattern3 }
};
