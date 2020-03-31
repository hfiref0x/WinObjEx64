/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       LOG.H
*
*  VERSION:     1.85
*
*  DATE:        25 Mar 2020
*
*  Header file for simplified log support.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define WOBJ_LOG_ENTRY_ERROR 0
#define WOBJ_LOG_ENTRY_SUCCESS 1
#define WOBJ_LOG_ENTRY_INFORMATION 2
#define WOBJ_LOG_ENTRY_WARNING 3

#define WOBJ_MAX_LOG_CAPACITY 2048

typedef struct _WOBJ_LOG_ENTRY {
    ULONG Type;
    LARGE_INTEGER LoggedTime;
    WCHAR MessageData[512];
} WOBJ_LOG_ENTRY, * PWOBJ_LOG_ENTRY;

typedef struct _WOBJ_LOG {
    BOOL Initialized;
    ULONG Count;
    CRITICAL_SECTION Lock;
    WOBJ_LOG_ENTRY *Entries;
} WOBJ_LOG, * PWOBJ_LOG;

typedef BOOL(CALLBACK* PLOGENUMERATECALLBACK)(
    _In_ WOBJ_LOG_ENTRY *Entry,
    _In_ PVOID CallbackContext);

VOID logCreate();
VOID logFree();

VOID logAdd(
    _In_ ULONG Type,
    _In_ WCHAR* Message);

BOOL logEnumEntries(
    _In_ PLOGENUMERATECALLBACK EnumCallback,
    _In_ PVOID CallbackContext);

VOID LogViewerShowDialog(
    _In_ HWND hwndParent);
