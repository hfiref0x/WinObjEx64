/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       EXTRASPN.C
*
*  VERSION:     1.30
*
*  DATE:        13 Aug 2015
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "extrasPN.h"
#include "propDlg.h"

static HWND PNDialog = NULL;
static LONG	PNDlgSortColumn = 0;
HWND PNListView = NULL;
BOOL bPNDlgSortInverse = FALSE;

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

	lpItem1 = supGetItemText(PNListView, (INT)lParam1, (INT)lParamSort, NULL);
	lpItem2 = supGetItemText(PNListView, (INT)lParam2, (INT)lParamSort, NULL);

	if ((lpItem1 == NULL) && (lpItem2 == NULL)) {
		nResult = 0;
		goto Done;
	}
	if ((lpItem1 == NULL) && (lpItem2 != NULL)) {
		nResult = (bSortInverse) ? 1 : -1;
		goto Done;
	}
	if ((lpItem2 == NULL) && (lpItem1 != NULL)) {
		nResult = (bSortInverse) ? -1 : 1;
		goto Done;
	}

	if (bSortInverse)
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
	INT             index;
	LIST_ENTRY      PrivateObjectList;
	BOOL            bResult = FALSE;
	POBJREF         ObjectInfo;
	PLIST_ENTRY     Entry;
	LVITEMW         lvitem;
//	WCHAR           szBuffer[MAX_PATH + 1];


	bResult = ObListCreate(&PrivateObjectList, TRUE);
	if (bResult == FALSE) {
		return bResult;
	}

	ObjectInfo = NULL;
	Entry = PrivateObjectList.Flink;
	while ((Entry != NULL)  && (Entry != &PrivateObjectList)) {
		ObjectInfo = CONTAINING_RECORD(Entry, OBJREF, ListEntry);
		if (ObjectInfo) {

			RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
			lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
			lvitem.iSubItem = 0;
			lvitem.pszText = ObjectInfo->ObjectName;
			lvitem.iItem = MAXINT;
//			lvitem.iImage = supGetObjectIndexByTypeName(objinf->TypeName.Buffer);
			index = ListView_InsertItem(PNListView, &lvitem);

			lvitem.mask = LVIF_TEXT;
			lvitem.iSubItem = 1;
			lvitem.pszText = L"TypeHere";
			lvitem.iItem = index;
			ListView_SetItem(PNListView, &lvitem);

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
//	LPWSTR			lpItemText;
	LVCOLUMNW		col;
	INT				c, k;

	if (nhdr == NULL)
		return;

	if (nhdr->hdr.idFrom != ID_NAMESPACELIST)
		return;

	switch (nhdr->hdr.code) {


	case LVN_COLUMNCLICK:
		bPNDlgSortInverse = !bPNDlgSortInverse;
		PNDlgSortColumn = ((NMLISTVIEW *)nhdr)->iSubItem;
		ListView_SortItemsEx(PNListView, &PNListCompareFunc, PNDlgSortColumn);

		RtlSecureZeroMemory(&col, sizeof(col));
		col.mask = LVCF_IMAGE;
		col.iImage = -1;

		for (c = 0; c < 2; c++)
			ListView_SetColumn(PNListView, c, &col);

		k = ImageList_GetImageCount(ListViewImages);
		if (bPNDlgSortInverse)
			col.iImage = k - 2;
		else
			col.iImage = k - 1;

		ListView_SetColumn(PNListView, ((NMLISTVIEW *)nhdr)->iSubItem, &col);
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
		PNDialog = NULL;
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
	LVCOLUMNW	col;
//	HICON		hIcon;

	MessageBox(hwndParent, TEXT("Under construction"), PROGRAM_NAME, 0);

	//allow only one dialog
	if (g_wobjDialogs[WOBJ_PNDLG_IDX]) {
		return;
	}

	PNDialog = CreateDialogParam(g_hInstance, MAKEINTRESOURCE(IDD_DIALOG_PNAMESPACE),
		hwndParent, &PNDialogProc, 0);

	if (PNDialog == NULL) {
		return;
	}

	g_wobjDialogs[WOBJ_PNDLG_IDX] = PNDialog;

	PNListView = GetDlgItem(PNDialog, ID_NAMESPACELIST);
	if (PNListView) {
		ListView_SetImageList(PNListView, ListViewImages, LVSIL_SMALL);
		ListView_SetExtendedListViewStyle(PNListView,
			LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

		//create ObjectList columns
		RtlSecureZeroMemory(&col, sizeof(col));
		col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER | LVCF_IMAGE;
		col.iSubItem = 1;
		col.pszText = L"Name";
		col.fmt = LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT;
		col.iOrder = 0;
		col.iImage = ImageList_GetImageCount(ListViewImages) - 1;
		col.cx = 300;
		ListView_InsertColumn(PNListView, 1, &col);

		col.iSubItem = 2;
		col.pszText = L"Type";
		col.iOrder = 1;
		col.iImage = -1;
		col.cx = 100;
		ListView_InsertColumn(PNListView, 2, &col);

		if (PNDlgQueryInfo()) {
			ShowWindow(GetDlgItem(PNDialog, ID_PNAMESPACESNOTALL), SW_HIDE);
			bPNDlgSortInverse = FALSE;
			ListView_SortItemsEx(PNListView, &PNListCompareFunc, 0);
		}
		else {
			ShowWindow(GetDlgItem(PNDialog, ID_PNAMESPACESNOTALL), SW_SHOW);
		}
	}
}
