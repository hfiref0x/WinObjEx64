/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       EXTRASSSDT.H
*
*  VERSION:     1.70
*
*  DATE:        30 Nov 2018
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

typedef struct _SERVICETABLEENTRY {
    ULONG ServiceId;
    ULONG_PTR Address;
    WCHAR Name[MAX_PATH + 1];
} SERVICETABLEENTRY, *PSERVICETABLEENTRY;

extern PSERVICETABLEENTRY g_pSDT;
extern PSERVICETABLEENTRY g_pSDTShadow;

typedef enum _SSDT_DLG_MODE {
    SST_Ntos = 0,
    SST_Win32k = 1,
    SST_Max
} SSDT_DLG_MODE;

VOID extrasCreateSSDTDialog(
    _In_ HWND hwndParent,
    _In_ SSDT_DLG_MODE Mode);
