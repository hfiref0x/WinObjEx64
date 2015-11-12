/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       EXTRAS.H
*
*  VERSION:     1.31
*
*  DATE:        11 Nov 2015
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
