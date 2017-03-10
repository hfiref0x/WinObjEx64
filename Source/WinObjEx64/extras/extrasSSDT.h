/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2016
*
*  TITLE:       EXTRASSSDT.H
*
*  VERSION:     1.44
*
*  DATE:        17 July 2016
*
*  Common header file for KiServiceTable dialog.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef struct _SERVICETABLEENTRY {
    ULONG ServiceId;
    ULONG_PTR Address;
    wchar_t Name[MAX_PATH + 1];
} SERVICETABLEENTRY, *PSERVICETABLEENTRY;

extern PSERVICETABLEENTRY g_SdtTable;
extern ULONG g_cSdtTable;
extern PVOID g_NtdllModule;

VOID extrasCreateSSDTDialog(
    _In_ HWND hwndParent
);
