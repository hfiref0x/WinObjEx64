/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2016
*
*  TITLE:       EXTRAS.H
*
*  VERSION:     1.40
*
*  DATE:        13 Feb 2016
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
	HIMAGELIST ImageList;
	LONG lvColumnToSort;
	LONG lvColumnCount;
	BOOL bInverseSort;
} EXTRASCONTEXT, *PEXTRASCONTEXT;

typedef INT(CALLBACK *DlgCompareFunction)(
	_In_ LPARAM lParam1,
	_In_ LPARAM lParam2,
	_In_ LPARAM lParamSort
	);

VOID extrasDlgHandleNotify(
	_In_ LPNMLISTVIEW nhdr,
	_In_ EXTRASCONTEXT *Context,
	_In_ DlgCompareFunction CompareFunc
	);

VOID extrasSimpleListResize(
	_In_ HWND hwndDlg
	);

VOID extrasSetDlgIcon(
	_In_ HWND hwndDlg
	);

VOID extrasShowPipeDialog(
	_In_ HWND hwndParent
	);

VOID extrasShowUserSharedDataDialog(
	_In_ HWND hwndParent
	);

VOID extrasShowPrivateNamespacesDialog(
	_In_ HWND hwndParent
	);

VOID extrasShowSSDTDialog(
	_In_ HWND hwndParent
	);

VOID extrasShowDriversDialog(
	_In_ HWND hwndParent
	);
