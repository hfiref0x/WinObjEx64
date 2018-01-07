/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       EXTRAS.H
*
*  VERSION:     1.52
*
*  DATE:        08 Jan 2018
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
    HWND SizeGrip;
    HIMAGELIST ImageList;
    LONG lvColumnToSort;
    LONG lvColumnCount;
    BOOL bInverseSort;
    union {
        ULONG_PTR Reserved;
        ULONG_PTR DialogMode;
    };
} EXTRASCONTEXT, *PEXTRASCONTEXT;

typedef struct _EXTRASCALLBACK {
    ULONG_PTR lParam;
    ULONG_PTR Value;
} EXTRASCALLBACK, *PEXTRASCALLBACK;

typedef INT(CALLBACK *DlgCompareFunction)(
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort
    );

typedef VOID(CALLBACK *CustomNotifyFunction)(
    _In_ LPNMLISTVIEW nhdr,
    _In_ EXTRASCONTEXT *Context,
    _In_opt_ PVOID Parameter
    );

VOID extrasDlgHandleNotify(
    _In_ LPNMLISTVIEW nhdr,
    _In_ EXTRASCONTEXT *Context,
    _In_ DlgCompareFunction CompareFunc,
    _In_opt_ CustomNotifyFunction CustomHandler,
    _In_opt_ PVOID CustomParameter);

VOID extrasSimpleListResize(
    _In_ HWND hwndDlg,
    _In_ HWND hwndSzGrip);

VOID extrasSetDlgIcon(
    _In_ HWND hwndDlg);

VOID extrasShowPipeDialog(
    _In_ HWND hwndParent);

VOID extrasShowMailslotsDialog(
    _In_ HWND hwndParent);

VOID extrasShowUserSharedDataDialog(
    _In_ HWND hwndParent);

VOID extrasShowPrivateNamespacesDialog(
    _In_ HWND hwndParent);

VOID extrasShowSSDTDialog(
    _In_ HWND hwndParent);

VOID extrasShowDriversDialog(
    _In_ HWND hwndParent);
