/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2024
*
*  TITLE:       PROPS.H
*
*  VERSION:     2.05
*
*  DATE:        11 Mar 2024
*
*  Common header file for properties dialog definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// Dialog procs.
//

INT_PTR CALLBACK AlpcPortListDialogProc(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam);

INT_PTR CALLBACK BasicPropDialogProc(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam);

INT_PTR CALLBACK DesktopListDialogProc(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam);

INT_PTR CALLBACK DriverRegistryDialogProc(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam);

INT_PTR CALLBACK ObjectDumpDialogProc(
    _In_  HWND hwndDlg,
    _In_  UINT uMsg,
    _In_  WPARAM wParam,
    _In_  LPARAM lParam);

INT_PTR CALLBACK ProcessListDialogProc(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam);

INT_PTR CALLBACK SectionPropertiesDialogProc(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam);

INT_PTR CALLBACK TokenPageDialogProc(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam);

INT_PTR CALLBACK TypePropDialogProc(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam);

//
// Security page.
//
HPROPSHEETPAGE propSecurityCreatePage(
    _In_ PROP_OBJECT_INFO* Context,
    _In_ POPENOBJECTMETHOD OpenObjectMethod,
    _In_opt_ PCLOSEOBJECTMETHOD CloseObjectMethod,
    _In_ ULONG psiFlags);

//
// Object dump
//
HTREEITEM propObDumpUlong(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpszName,
    _In_opt_ LPWSTR lpszDesc,
    _In_ ULONG Value,
    _In_ BOOL HexDump,
    _In_ BOOL IsUShort,
    _In_ COLORREF BgColor,
    _In_ COLORREF FontColor);

VOID propObDumpUlong64(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpszName,
    _In_opt_ LPWSTR lpszDesc,
    _In_ ULONG64 Value,
    _In_ BOOL OutAsHex,
    _In_ COLORREF BgColor,
    _In_ COLORREF FontColor);

VOID propObDumpByte(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpszName,
    _In_opt_ LPWSTR lpszDesc,
    _In_ BYTE Value,
    _In_ COLORREF BgColor,
    _In_ COLORREF FontColor,
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
    _In_ COLORREF BgColor,
    _In_ COLORREF FontColor);

HTREEITEM propObDumpLong(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpszName,
    _In_opt_ LPWSTR lpszDesc,
    _In_ LONG Value,
    _In_ BOOL HexDump,
    _In_ COLORREF BgColor,
    _In_ COLORREF FontColor);

VOID propObDumpLong64(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR lpszName,
    _In_opt_ LPWSTR lpszDesc,
    _In_opt_ LONG64 Value,
    _In_ BOOL OutAsHex,
    _In_ COLORREF BgColor,
    _In_ COLORREF FontColor);

VOID propObDumpListEntry(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR ListEntryName,
    _In_opt_ PLIST_ENTRY ListEntry);

VOID propObDumpUSHORT(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR Name,
    _In_ USHORT Value,
    _In_ BOOLEAN HexOutput);

VOID propObDumpUnicodeString(
    _In_ HWND TreeList,
    _In_ HTREEITEM hParent,
    _In_ LPWSTR StringName,
    _In_ PUNICODE_STRING InputString,
    _In_ BOOLEAN IsKernelPointer);

VOID propDumpEnumWithNames(
    _In_ HWND TreeList,
    _In_ HTREEITEM ParentItem,
    _In_ LPWSTR EnumName,
    _In_ ULONG EnumValue,
    _In_ PVALUE_DESC EnumNames,
    _In_ ULONG EnumNamesCount);
