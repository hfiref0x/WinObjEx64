/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2016
*
*  TITLE:       PROPOBJECTDUMP.H
*
*  VERSION:     1.41
*
*  DATE:        01 Mar 2016
*
*  Common header file for the object dump support.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef struct _TL_SUBITEMS_FIXED {
	ULONG		ColorFlags;
	COLORREF	BgColor;
	COLORREF	FontColor;
	ULONG		Count;
	LPTSTR		Text[2];
} TL_SUBITEMS_FIXED, *PTL_SUBITEMS_FIXED;

VOID ObDumpDriverObject(
	_In_ PROP_OBJECT_INFO *Context,
	_In_ HWND hwndDlg
	);

VOID ObDumpDeviceObject(
	_In_ PROP_OBJECT_INFO *Context,
	_In_ HWND hwndDlg
	);

VOID ObDumpDirectoryObject(
	_In_ PROP_OBJECT_INFO *Context,
	_In_ HWND hwndDlg
	);

INT_PTR CALLBACK ObjectDumpDialogProc(
	_In_  HWND hwndDlg,
	_In_  UINT uMsg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
	);

VOID ObDumpUlong(
	HWND TreeList,
	HTREEITEM hParent,
	LPWSTR lpszName,
	LPWSTR lpszDesc, 
	ULONG Value,
	BOOL HexDump,
	BOOL IsUShort,
	COLORREF BgColor,
	COLORREF FontColor
	);

VOID ObDumpByte(
	HWND TreeList,
	HTREEITEM hParent,
	LPWSTR lpszName,
	LPWSTR lpszDesc,
	BYTE Value,
	COLORREF BgColor,
	COLORREF FontColor,
	BOOL IsBool
	);

VOID ObDumpAddress(
	HWND TreeList,
	HTREEITEM hParent,
	LPWSTR lpszName,
	LPWSTR lpszDesc, 
	PVOID Address,
	COLORREF BgColor,
	COLORREF FontColor
	);

VOID ObDumpULargeInteger(
	HWND TreeList,
	HTREEITEM hParent,
	LPWSTR ListEntryName,
	PULARGE_INTEGER Value
	);

VOID ObDumpListEntry(
	HWND TreeList,
	HTREEITEM hParent,
	LPWSTR ListEntryName,
	PLIST_ENTRY ListEntry
	);

HTREEITEM TreeListAddItem(
	HWND TreeList,
	HTREEITEM hParent,
	UINT mask,
	UINT state,
	UINT stateMask,
	LPWSTR pszText,
	PVOID subitems
	);
