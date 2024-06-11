/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2021 - 2024
*
*  TITLE:       SUP.H
*
*  VERSION:     1.14
*
*  DATE:        04 Jun 2024
* 
*  Sonar plugin support definitions and declarations.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

PVOID HeapMemoryAlloc(
    _In_ SIZE_T Size);

BOOL HeapMemoryFree(
    _In_ PVOID Memory);

BOOL supGetWin32FileName(
    _In_ LPWSTR FileName,
    _Inout_ LPWSTR Win32FileName,
    _In_ SIZE_T ccWin32FileName);

VOID supClipboardCopy(
    _In_ LPWSTR lpText,
    _In_ SIZE_T cbText);

BOOL supTreeListAddCopyValueItem(
    _In_ HMENU hMenu,
    _In_ HWND hwndTreeList,
    _In_ UINT uId,
    _In_ UINT uPos,
    _In_ LPARAM lParam,
    _In_ INT* pSubItemHit);

LPWSTR supGetItemText(
    _In_ HWND ListView,
    _In_ INT nItem,
    _In_ INT nSubItem,
    _Out_opt_ PSIZE_T lpSize);

LPWSTR supGetItemText2(
    _In_ HWND ListView,
    _In_ INT nItem,
    _In_ INT nSubItem,
    _In_ WCHAR* pszText,
    _In_ UINT cchText);

BOOL supListViewAddCopyValueItem(
    _In_ HMENU hMenu,
    _In_ HWND hwndLv,
    _In_ UINT uId,
    _In_ UINT uPos,
    _In_ POINT* lpPoint,
    _Out_ INT* pItemHit,
    _Out_ INT* pColumnHit);

BOOL supListViewCopyItemValueToClipboard(
    _In_ HWND hwndListView,
    _In_ INT iItem,
    _In_ INT iSubItem);

BOOL supTreeListCopyItemValueToClipboard(
    _In_ HWND hwndTreeList,
    _In_ INT tlSubItemHit);

INT supGetMaxCompareTwoFixedStrings(
    _In_ HWND ListView,
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort,
    _In_ BOOL Inverse);

INT supGetMaxOfTwoU64FromHex(
    _In_ HWND ListView,
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort,
    _In_ BOOL Inverse);
