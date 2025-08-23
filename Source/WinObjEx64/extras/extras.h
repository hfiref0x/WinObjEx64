/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2025
*
*  TITLE:       EXTRAS.H
*
*  VERSION:     2.09
*
*  DATE:        21 Aug 2025
*
*  Common header file for Extras dialogs.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef struct _EXTRASCONTEXT {
    HWND hwndDlg;
    HWND ListView;
    HWND TreeList;
    HWND StatusBar;
    PVOID TooltipInfo;
    HIMAGELIST ImageList;
    INT lvColumnToSort;
    INT lvColumnCount;
    INT lvColumnHit;
    INT lvItemHit;
    INT tlSubItemHit;
    BOOL bInverseSort;
    union {
        ULONG_PTR Reserved;
        ULONG_PTR DialogMode;
    };
    HICON ObjectIcon;
    HICON DialogIcon;
} EXTRASCONTEXT, *PEXTRASCONTEXT;

typedef struct _EXTRASCALLBACK {
    ULONG_PTR lParam;
    ULONG_PTR Value;
} EXTRASCALLBACK, *PEXTRASCALLBACK;

typedef enum _IPC_DLG_MODE {
    IpcModeNamedPipes = 0,
    IpcModeMailSlots = 1,
    IpcMaxMode = 2
} IPC_DLG_MODE;

typedef enum _DRIVERS_DLG_MODE {
    DrvModeNormal = 0,
    DrvModeUnloaded = 1,
    DrvModeMax = 2
} DRIVERS_DLG_MODE;

typedef enum _SSDT_DLG_MODE {
    SST_Ntos = 0,
    SST_Win32k = 1,
    SST_Max = 2
} SSDT_DLG_MODE;

typedef INT(CALLBACK *DlgCompareFunction)(
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort
    );

typedef BOOL(CALLBACK *CustomNotifyFunction)(
    _In_ LPNMLISTVIEW nhdr,
    _In_ EXTRASCONTEXT *Context,
    _In_opt_ PVOID Parameter
    );

VOID extrasSimpleListResize(
    _In_ HWND hwndDlg);

VOID extrasSetDlgIcon(
    _In_ EXTRASCONTEXT* Context);

VOID extrasRemoveDlgIcon(
    _In_ EXTRASCONTEXT* Context);

VOID extrasShowDialogById(
    _In_ WORD DialogId);

VOID extrasHandleSettingsChange(
    EXTRASCONTEXT* Context);

//
// Dialog handlers.
//

VOID extrasCreateCallbacksDialog(
    VOID);

VOID extrasCreateCmOptDialog(
    VOID);

VOID extrasCreateDriversDialog(
    _In_ DRIVERS_DLG_MODE Mode);

VOID extrasCreateIpcDialog(
    _In_ IPC_DLG_MODE Mode);

VOID extrasCreatePNDialog(
    VOID);

VOID extrasCreatePsListDialog(
    VOID);

VOID extrasCreateSLCacheDialog(
    VOID);

VOID extrasCreateSSDTDialog(
    _In_ SSDT_DLG_MODE Mode);

VOID extrasCreateUsdDialog(
    VOID);
