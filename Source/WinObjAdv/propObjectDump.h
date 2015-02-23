/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       PROPOBJECTDUMP.H
*
*  VERSION:     1.00
*
*  DATE:        19 Feb 2015
*
*  Common header file for the object dump support.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
typedef struct _TL_SUBITEMS_FIXED {
	ULONG		ColorFlags;
	COLORREF	BgColor;
	COLORREF	FontColor;
	ULONG		Count;
	LPTSTR		Text[2];
} TL_SUBITEMS_FIXED, *PTL_SUBITEMS_FIXED;

VOID ObDumpDriverObject(
	PROP_OBJECT_INFO *Context,
	HWND hwndDlg
	);

VOID ObDumpDeviceObject(
	PROP_OBJECT_INFO *Context,
	HWND hwndDlg
	);

VOID ObDumpDirectoryObject(
	PROP_OBJECT_INFO *Context,
	HWND hwndDlg
	);

INT_PTR CALLBACK ObjectDumpDialogProc(
	_In_  HWND hwndDlg,
	_In_  UINT uMsg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
	);