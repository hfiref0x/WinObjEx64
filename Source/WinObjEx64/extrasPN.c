/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       EXTRASPN.C
*
*  VERSION:     1.31
*
*  DATE:        11 Nov 2015
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "extras.h"
#include "extrasPN.h"
#include "propDlg.h"

EXTRASCONTEXT PnDlgContext;

#define T_NAMESPACEID          TEXT("Ns%lu")
#define T_NAMESPACEOBJECTCNT   TEXT("Total Object(s): %lu")
#define T_NAMESPACEQUERYFAILED TEXT("Unable to list namespaces! Make sure you run this program as Admin and Windows is in a DEBUG mode.")

/*
* PNListCompareFunc
*
* Purpose:
*
* Main window listview comparer function.
*
*/
INT CALLBACK PNListCompareFunc(
	_In_ LPARAM lParam1,
	_In_ LPARAM lParam2,
	_In_ LPARAM lParamSort
	)
{
	LPWSTR lpItem1, lpItem2;
	INT nResult = 0;

	lpItem1 = supGetItemText(PnDlgContext.ListView, (INT)lParam1, (INT)lParamSort, NULL);
	lpItem2 = supGetItemText(PnDlgContext.ListView, (INT)lParam2, (INT)lParamSort, NULL);

	if ((lpItem1 == NULL) && (lpItem2 == NULL)) {
		nResult = 0;
		goto Done;
	}
	if ((lpItem1 == NULL) && (lpItem2 != NULL)) {
		nResult = (PnDlgContext.bInverseSort) ? 1 : -1;
		goto Done;
	}
	if ((lpItem2 == NULL) && (lpItem1 != NULL)) {
		nResult = (PnDlgContext.bInverseSort) ? -1 : 1;
		goto Done;
	}

	if (PnDlgContext.bInverseSort)
		nResult = _strcmpi(lpItem2, lpItem1);
	else
		nResult = _strcmpi(lpItem1, lpItem2);

Done:
	if (lpItem1) {
		HeapFree(GetProcessHeap(), 0, lpItem1);
	}
	if (lpItem2) {
		HeapFree(GetProcessHeap(), 0, lpItem2);
	}
	return nResult;
}

BOOL PNDlgQueryInfo(
	VOID
	)
{
	INT           index;
	UINT          ConvertedTypeIndex;
	LIST_ENTRY    PrivateObjectList;
	BOOL          bResult = FALSE;
	POBJREF       ObjectInfo;
	PLIST_ENTRY   Entry;
	LVITEMW       lvitem;
	LPCWSTR       TypeName;
	WCHAR         szBuffer[MAX_PATH + 1];


	bResult = ObListCreate(&PrivateObjectList, TRUE);
	if (bResult == FALSE) {
		return bResult;
	}

	ObjectInfo = NULL;
	Entry = PrivateObjectList.Flink;
	while ((Entry != NULL)  && (Entry != &PrivateObjectList)) {
		ObjectInfo = CONTAINING_RECORD(Entry, OBJREF, ListEntry);
		if (ObjectInfo) {

			ConvertedTypeIndex = supGetObjectNameIndexByTypeIndex(
				(PVOID)ObjectInfo->ObjectAddress, ObjectInfo->TypeIndex);

			TypeName = T_ObjectNames[ConvertedTypeIndex];

			//Name
			RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
			lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
			lvitem.iSubItem = 0;
			lvitem.iItem = MAXINT;
			lvitem.iImage = ConvertedTypeIndex;
			lvitem.pszText = ObjectInfo->ObjectName;
			index = ListView_InsertItem(PnDlgContext.ListView, &lvitem);

			//Type
			lvitem.mask = LVIF_TEXT;
			lvitem.iSubItem = 1;
			lvitem.pszText = (LPWSTR)TypeName;
			lvitem.iItem = index;
			ListView_SetItem(PnDlgContext.ListView, &lvitem);

			//Namespace id
			lvitem.mask = LVIF_TEXT;
			lvitem.iSubItem = 2;
			lvitem.iItem = index;
			RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
			wsprintf(szBuffer, T_NAMESPACEID, ObjectInfo->NamespaceId);
			lvitem.pszText = szBuffer;
			ListView_SetItem(PnDlgContext.ListView, &lvitem);
		}
		Entry = Entry->Flink;
	}
	ObListDestroy(&PrivateObjectList);
	return bResult;
}

/*
* PNDlgHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for PNDialog listview.
*
*/
VOID PNDlgHandleNotify(
	LPNMLISTVIEW	nhdr
	)
{
	LVCOLUMNW		col;
	INT				c, k;

	if (nhdr == NULL)
		return;

	if (nhdr->hdr.idFrom != ID_NAMESPACELIST)
		return;

	switch (nhdr->hdr.code) {


	case LVN_COLUMNCLICK:
		
		PnDlgContext.bInverseSort = !PnDlgContext.bInverseSort;
		PnDlgContext.lvColumnToSort = ((NMLISTVIEW *)nhdr)->iSubItem;
		ListView_SortItemsEx(PnDlgContext.ListView, &PNListCompareFunc, PnDlgContext.lvColumnToSort);

		RtlSecureZeroMemory(&col, sizeof(col));
		col.mask = LVCF_IMAGE;
		col.iImage = -1;

		for (c = 0; c < PnDlgContext.lvColumnCount; c++)
			ListView_SetColumn(PnDlgContext.ListView, c, &col);

		k = ImageList_GetImageCount(ListViewImages);
		if (PnDlgContext.bInverseSort)
			col.iImage = k - 2;
		else
			col.iImage = k - 1;

		ListView_SetColumn(PnDlgContext.ListView, ((NMLISTVIEW *)nhdr)->iSubItem, &col);
		break;

	default:
		break;
	}
}

/*
* PNDialogProc
*
* Purpose:
*
* Private Namespace Dialog window procedure.
*
*/
INT_PTR CALLBACK PNDialogProc(
	_In_  HWND hwndDlg,
	_In_  UINT uMsg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
	)
{
	LPNMLISTVIEW nhdr = (LPNMLISTVIEW)lParam;

	switch (uMsg) {
	case WM_NOTIFY:
		PNDlgHandleNotify(nhdr);
		break;

	case WM_INITDIALOG:
		supCenterWindow(hwndDlg);
		break;

	case WM_CLOSE:
		DestroyWindow(hwndDlg);
		g_wobjDialogs[WOBJ_PNDLG_IDX] = NULL;
		return TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDCANCEL) {
			SendMessage(hwndDlg, WM_CLOSE, 0, 0);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

/*
* extrasCreatePNDialog
*
* Purpose:
*
* Create and initialize Private Namespaces Dialog.
*
*/
VOID extrasCreatePNDialog(
	_In_ HWND hwndParent
	)
{
	LVCOLUMNW   col;
	WCHAR       szBuffer[MAX_PATH + 1];


	//allow only one dialog
	if (g_wobjDialogs[WOBJ_PNDLG_IDX]) {
		SetActiveWindow(g_wobjDialogs[WOBJ_PNDLG_IDX]);
		return;
	}

	RtlSecureZeroMemory(&PnDlgContext, sizeof(PnDlgContext));
	PnDlgContext.hwndDlg = CreateDialogParam(g_hInstance, MAKEINTRESOURCE(IDD_DIALOG_PNAMESPACE),
		hwndParent, &PNDialogProc, 0);

	if (PnDlgContext.hwndDlg == NULL) {
		return;
	}

	g_wobjDialogs[WOBJ_PNDLG_IDX] = PnDlgContext.hwndDlg;

	PnDlgContext.ListView = GetDlgItem(PnDlgContext.hwndDlg, ID_NAMESPACELIST);
	if (PnDlgContext.ListView) {
		ListView_SetImageList(PnDlgContext.ListView, ListViewImages, LVSIL_SMALL);
		ListView_SetExtendedListViewStyle(PnDlgContext.ListView,
			LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

		//create ObjectList columns
		RtlSecureZeroMemory(&col, sizeof(col));
		col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER | LVCF_IMAGE;
		col.iSubItem = 1;
		col.pszText = L"Name";
		col.fmt = LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT;
		col.iOrder = 0;
		col.iImage = ImageList_GetImageCount(ListViewImages) - 1;
		col.cx = 400;
		ListView_InsertColumn(PnDlgContext.ListView, 1, &col);

		col.iSubItem = 2;
		col.pszText = L"Type";
		col.iOrder = 1;
		col.iImage = -1;
		col.cx = 100;
		ListView_InsertColumn(PnDlgContext.ListView, 2, &col);

		col.iSubItem = 3;
		col.pszText = L"Namespace";
		col.iOrder = 2;
		col.iImage = -1;
		col.cx = 100;
		ListView_InsertColumn(PnDlgContext.ListView, 3, &col);

		//remember columns count
		PnDlgContext.lvColumnCount = 3;

		if (PNDlgQueryInfo()) {
			ListView_SortItemsEx(PnDlgContext.ListView, &PNListCompareFunc, 0);
			RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
			wsprintfW(szBuffer, T_NAMESPACEOBJECTCNT, ListView_GetItemCount(PnDlgContext.ListView));
			SetDlgItemText(PnDlgContext.hwndDlg, ID_PNAMESPACESINFO, szBuffer);
		}
		else {
			SetDlgItemText(PnDlgContext.hwndDlg, ID_PNAMESPACESINFO, T_NAMESPACEQUERYFAILED);
		}
	}
}
