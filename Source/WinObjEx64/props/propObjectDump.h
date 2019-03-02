/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019
*
*  TITLE:       PROPOBJECTDUMP.H
*
*  VERSION:     1.72
*
*  DATE:        04 Feb 2019
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

VOID propObDumpUlong(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpszName,
    _In_opt_ LPWSTR lpszDesc, //additional text to be displayed
    _In_ ULONG Value,
    _In_ BOOL HexDump,
    _In_ BOOL IsUShort,
    _In_opt_ COLORREF BgColor,
    _In_opt_ COLORREF FontColor);

VOID propObDumpByte(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpszName,
    _In_opt_ LPWSTR lpszDesc,
    _In_ BYTE Value,
    _In_opt_ COLORREF BgColor,
    _In_opt_ COLORREF FontColor,
    _In_ BOOL IsBool);
