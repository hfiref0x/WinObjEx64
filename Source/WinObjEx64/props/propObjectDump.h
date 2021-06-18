/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2021
*
*  TITLE:       PROPOBJECTDUMP.H
*
*  VERSION:     1.90
*
*  DATE:        11 May 2021
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

INT_PTR CALLBACK ObjectDumpDialogProc(
    _In_  HWND hwndDlg,
    _In_  UINT uMsg,
    _In_  WPARAM wParam,
    _In_  LPARAM lParam);

HTREEITEM propObDumpUlong(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpszName,
    _In_opt_ LPWSTR lpszDesc,
    _In_ ULONG Value,
    _In_ BOOL HexDump,
    _In_ BOOL IsUShort,
    _In_opt_ COLORREF BgColor,
    _In_opt_ COLORREF FontColor);

VOID propObDumpUlong64(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpszName,
    _In_opt_ LPWSTR lpszDesc,
    _In_opt_ ULONG64 Value,
    _In_ BOOL OutAsHex,
    _In_ COLORREF BgColor,
    _In_ COLORREF FontColor);

VOID propObDumpByte(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpszName,
    _In_opt_ LPWSTR lpszDesc,
    _In_ BYTE Value,
    _In_opt_ COLORREF BgColor,
    _In_opt_ COLORREF FontColor,
    _In_ BOOL IsBool);

HTREEITEM propObDumpAddress(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpszName,
    _In_opt_ LPWSTR lpszDesc,
    _In_opt_ PVOID Address,
    _In_ COLORREF BgColor,
    _In_ COLORREF FontColor);

HTREEITEM propObDumpSetString(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpszName,
    _In_opt_ LPWSTR lpszDesc,
    _In_opt_ LPWSTR lpszValue,
    _In_opt_ COLORREF BgColor,
    _In_opt_ COLORREF FontColor);

HTREEITEM propObDumpLong(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpszName,
    _In_opt_ LPWSTR lpszDesc,
    _In_ LONG Value,
    _In_ BOOL HexDump,
    _In_opt_ COLORREF BgColor,
    _In_opt_ COLORREF FontColor);

VOID propObDumpListEntry(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR ListEntryName,
    _In_opt_ PLIST_ENTRY ListEntry);
