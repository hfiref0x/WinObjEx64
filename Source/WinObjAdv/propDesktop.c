/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       PROPDESKTOP.C
*
*  VERSION:     1.10
*
*  DATE:        28 Feb 2015
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "propDlg.h"
#include "propDesktop.h"
#include <Sddl.h>

//page imagelist
HIMAGELIST DesktopImageList = NULL;
//page listview
HWND DesktopList = NULL;
//column to sort
static LONG	DesktopListSortColumn = 0;
//sort direction
BOOL bDesktopListSortInverse = FALSE;

/*
* DesktopListEnumProc
*
* Purpose:
*
* EnumDesktops callback.
*
*/
BOOL CALLBACK DesktopListEnumProc(
	_In_  LPWSTR lpszDesktop,
	_In_  LPARAM lParam
	)
{
	PROP_OBJECT_INFO *Context;

	BOOL		bSucc;
	INT			nIndex;
	DWORD		bytesNeeded, dwDesktopHeapSize;
	LPWSTR		lpName;
	PSID		pSID;
	SIZE_T		sz;
	HDESK		hDesktop;
	LPWSTR		StringSid;
	LVITEMW		lvitem;
	WCHAR		szBuffer[MAX_PATH];

	Context = (PROP_OBJECT_INFO*)lParam;
	if (Context == NULL) {
		return FALSE;
	}

	sz = (_strlenW(lpszDesktop) * sizeof(WCHAR)) +
		(_strlenW(Context->lpObjectName) * sizeof(WCHAR)) +
		(2 * sizeof(WCHAR)) + sizeof(UNICODE_NULL);

	lpName = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
	//not enough memory? cancel enum
	if (lpName == NULL) {
		return 0;
	}
	
	_strcpyW(lpName, Context->lpObjectName);
	_strcatW(lpName, L"\\");
	_strcatW(lpName, lpszDesktop);

	//Name
	RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
	lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
	lvitem.iImage = 0;
	lvitem.iSubItem = 0;
	lvitem.pszText = lpName;
	lvitem.iItem = MAXINT;
	nIndex = ListView_InsertItem(DesktopList, &lvitem);

	HeapFree(GetProcessHeap(), 0, lpName);

	//Query desktop objects information
	bSucc = FALSE;
	StringSid = NULL;
	hDesktop = OpenDesktop(lpszDesktop, 0, FALSE, DESKTOP_READOBJECTS);
	if (hDesktop) {

		//Query SID
		bytesNeeded = 0;
		GetUserObjectInformation(hDesktop, UOI_USER_SID, NULL, 0, &bytesNeeded);
		//user associated with desktop present, query sid
		if (bytesNeeded) {
			//allocate memory for sid
			pSID = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytesNeeded);
			if (pSID) {
				if (GetUserObjectInformation(hDesktop,
					UOI_USER_SID, pSID, bytesNeeded, &bytesNeeded))
				{
					bSucc = ConvertSidToStringSid(pSID, &StringSid);
				}
				HeapFree(GetProcessHeap(), 0, pSID);
			}
		}

		//Add SID string to the list
		if (bSucc && StringSid) {
			lvitem.mask = LVIF_TEXT;
			lvitem.iSubItem = 1;
			lvitem.pszText = StringSid;
			lvitem.iItem = nIndex;
			ListView_SetItem(DesktopList, &lvitem);
			LocalFree(StringSid);
		}

		//Add Desktop Heap Size, returned in KBytes
		dwDesktopHeapSize = 0;
		if (GetUserObjectInformation(hDesktop, UOI_HEAPSIZE,
			&dwDesktopHeapSize, sizeof(dwDesktopHeapSize), &bytesNeeded)) {

			RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
			ultostr(dwDesktopHeapSize / 1024, szBuffer);
			_strcatW(szBuffer, L" Mb");

			lvitem.mask = LVIF_TEXT;
			lvitem.iSubItem = 2;
			lvitem.pszText = szBuffer;
			lvitem.iItem = nIndex;
			ListView_SetItem(DesktopList, &lvitem);
		}
		CloseDesktop(hDesktop);
	}
	return TRUE;
}

/*
* DesktopListSetInfo
*
* Purpose:
*
* Query information and fill listview.
* Called each time when page became visible.
*
*/
VOID DesktopListSetInfo(
	_In_ PROP_OBJECT_INFO *Context,
	_In_ HWND hwndDlg
	)
{
	BOOL		bResult = FALSE;
	HWINSTA		hObject;

	if (Context == NULL) {
		return;
	}

	ListView_DeleteAllItems(DesktopList);

	hObject = OpenWindowStation(Context->lpObjectName, FALSE, WINSTA_ENUMDESKTOPS);
	if (hObject) {
		EnumDesktops(hObject, DesktopListEnumProc, (LPARAM)Context);
		CloseWindowStation(hObject);
		bResult = TRUE;
	}
	ShowWindow(GetDlgItem(hwndDlg, ID_DESKTOPSNOTALL), (bResult != TRUE) ? SW_SHOW : SW_HIDE);
}

/*
* DesktopListCreate
*
* Purpose:
*
* Initialize listview for desktop list.
* Called once.
*
*/
VOID DesktopListCreate(
	_In_ HWND hwndDlg
	)
{
	LVCOLUMNW	col;
	HANDLE		tmpb;

	DesktopList = GetDlgItem(hwndDlg, ID_DESKTOPSLIST);
	if (DesktopList == NULL)
		return;

	DesktopImageList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 8, 8);
	if (DesktopImageList) {

		//desktop image
		tmpb = LoadImage(g_hInstance, MAKEINTRESOURCE(IDI_ICON_DESKTOP), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
		if (tmpb) {
			ImageList_ReplaceIcon(DesktopImageList, -1, tmpb);
			DestroyIcon(tmpb);
		}

		//sort images
		tmpb = LoadImage(g_hInstance, MAKEINTRESOURCE(IDI_ICON_SORTUP), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
		if (tmpb) {
			ImageList_ReplaceIcon(DesktopImageList, -1, tmpb);
			DestroyIcon(tmpb);
		}
		tmpb = LoadImage(g_hInstance, MAKEINTRESOURCE(IDI_ICON_SORTDOWN), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
		if (tmpb) {
			ImageList_ReplaceIcon(DesktopImageList, -1, tmpb);
			DestroyIcon(tmpb);
		}

		ListView_SetImageList(DesktopList, DesktopImageList, LVSIL_SMALL);
	}

	ListView_SetExtendedListViewStyle(DesktopList, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

	RtlSecureZeroMemory(&col, sizeof(col));
	col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER | LVCF_IMAGE;
	col.iSubItem = 1;
	col.pszText = L"Name";
	col.fmt = LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT;
	col.iOrder = 0;
	col.iImage = 2;
	col.cx = 200;
	ListView_InsertColumn(DesktopList, 1, &col);

	col.iSubItem = 2;
	col.pszText = L"SID";
	col.iOrder = 1;
	col.iImage = -1;
	col.cx = 100;
	ListView_InsertColumn(DesktopList, 2, &col);

	col.iSubItem = 3;
	col.pszText = L"Heap Size";
	col.iOrder = 2;
	col.iImage = -1;
	col.cx = 100;
	ListView_InsertColumn(DesktopList, 3, &col);
}

/*
* DesktopListCompareFunc
*
* Purpose:
*
* Desktop page listview comparer function.
*
*/
INT CALLBACK DesktopListCompareFunc(
	_In_ LPARAM lParam1,
	_In_ LPARAM lParam2,
	_In_ LPARAM lParamSort
	)
{
	LPWSTR lpItem1, lpItem2;
	INT nResult;

	lpItem1 = supGetItemText(DesktopList, (INT)lParam1, (INT)lParamSort, NULL);
	if (lpItem1 == NULL)
		return 0;

	lpItem2 = supGetItemText(DesktopList, (INT)lParam2, (INT)lParamSort, NULL);
	if (lpItem2 == NULL)
		return 0;

	if (bDesktopListSortInverse)
		nResult = _strcmpi(lpItem2, lpItem1);
	else
		nResult = _strcmpi(lpItem1, lpItem2);

	HeapFree(GetProcessHeap(), 0, lpItem1);
	HeapFree(GetProcessHeap(), 0, lpItem2);
	return nResult;
}

/*
* DesktopListHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for Desktop page listview.
*
*/
VOID DesktopListHandleNotify(
	HWND			hwndDlg,
	LPNMLISTVIEW	nhdr
	)
{
	LVCOLUMNW	col;
	INT			c;
	SIZE_T		sz, i, l;
	LPWSTR		lpItemText, lpName;

	if (nhdr == NULL) {
		return;
	}

	if (nhdr->hdr.idFrom != ID_DESKTOPSLIST) {
		return;
	}

	switch (nhdr->hdr.code) {

	case LVN_COLUMNCLICK:
		bDesktopListSortInverse = !bDesktopListSortInverse;
		DesktopListSortColumn = ((NMLISTVIEW *)nhdr)->iSubItem;
		ListView_SortItemsEx(DesktopList, &DesktopListCompareFunc, DesktopListSortColumn);

		RtlSecureZeroMemory(&col, sizeof(col));
		col.mask = LVCF_IMAGE;
		col.iImage = -1;

		for (c = 0; c < 3; c++) {
			ListView_SetColumn(DesktopList, c, &col);
		}

		if (bDesktopListSortInverse)
			col.iImage = 1;
		else
			col.iImage = 2;

		ListView_SetColumn(DesktopList, ((NMLISTVIEW *)nhdr)->iSubItem, &col);
		break;

	case NM_DBLCLK:
		/*
		* A very basic support for this type
		* desktop described by win32k PDESKTOP structure which is totally undocumented
		*/
		sz = 0;
		lpItemText = supGetItemText(DesktopList, ListView_GetSelectionMark(DesktopList), 0, &sz);
		if (lpItemText) {
			l = 0;
			for (i = 0; i<sz; i++)
				if (lpItemText[i] == L'\\')
					l = i + 1;
			lpName = &lpItemText[l];
			//hwndDlg set to mainwindow on purpose
			propCreateDialog(hwndDlg, lpName, T_ObjectNames[TYPE_DESKTOP], NULL);
			HeapFree(GetProcessHeap(), 0, lpItemText);
		}
		break;

	default:
		break;
	}
}

/*
* DesktopListDialogProc
*
* Purpose:
*
* Desktop list page.
*
* WM_INITDIALOG - Initialize listview.
* WM_NOTIFY - Handle list view notifications.
* WM_SHOWWINDOW - Collect desktop info and fill list.
* WM_DESTROY - Free image list.
*
*/
INT_PTR CALLBACK DesktopListDialogProc(
	_In_  HWND hwndDlg,
	_In_  UINT uMsg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
	)
{
	LPNMLISTVIEW	nhdr = NULL;
	PROPSHEETPAGE *pSheet;
	PROP_OBJECT_INFO *Context = NULL;

	switch (uMsg) {

	case WM_SHOWWINDOW:
		if (wParam) {
			Context = GetProp(hwndDlg, T_PROPCONTEXT);
			DesktopListSetInfo(Context, hwndDlg);
			if (DesktopList) {
				ListView_SortItemsEx(DesktopList, &DesktopListCompareFunc, DesktopListSortColumn);
			}
			return 1;
		}
		break;

	case WM_NOTIFY:
		nhdr = (LPNMLISTVIEW)lParam;
		DesktopListHandleNotify(hwndDlg, nhdr);
		return 1;
		break;

	case WM_DESTROY:
		if (DesktopImageList) {
			ImageList_Destroy(DesktopImageList);
		}
		RemoveProp(hwndDlg, T_PROPCONTEXT);
		break;

	case WM_INITDIALOG:
		pSheet = (PROPSHEETPAGE*)lParam;
		if (pSheet) {
			SetProp(hwndDlg, T_PROPCONTEXT, (HANDLE)pSheet->lParam);
		}
		DesktopListCreate(hwndDlg);
		return 1;
		break;

	}
	return 0;
}