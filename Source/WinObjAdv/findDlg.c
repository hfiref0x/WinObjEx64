/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       FINDDLG.C
*
*  VERSION:     1.00
*
*  DATE:        17 Feb 2015
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "findDlg.h"

static HWND FindDlgList;

static LONG sizes_init = 0, dx1, dx2, dx3, dx4, dx5, dx6, dx7, dx8, dx9, dx10, dx11, dx12, dx13;

//local FindDlg variable controlling sorting direction
BOOL bFindDlgSortInverse = FALSE;

static LONG	FindDlgSortColumn = 0;

/*
* FindDlgCompareFunc
*
* Purpose:
*
* FindDlg listview comparer function.
*
*/
INT CALLBACK FindDlgCompareFunc(
	_In_ LPARAM lParam1,
	_In_ LPARAM lParam2,
	_In_ LPARAM lParamSort
	)
{
	LPWSTR lpItem1, lpItem2;
	INT nResult;
	
	lpItem1 = supGetItemText(FindDlgList, (INT)lParam1, (INT)lParamSort, NULL);
	if (lpItem1 == NULL)
		return 0;

	lpItem2 = supGetItemText(FindDlgList, (INT)lParam2, (INT)lParamSort, NULL);
	if (lpItem2 == NULL)
		return 0;

	if (bFindDlgSortInverse)
		nResult = _strcmpi(lpItem2, lpItem1);
	else
		nResult = _strcmpi(lpItem1, lpItem2);

	HeapFree(GetProcessHeap(), 0, lpItem1);
	HeapFree(GetProcessHeap(), 0, lpItem2);
	return nResult;
}

/*
* FindDlgAddListItem
*
* Purpose:
*
* Add item to listview.
*
*/
VOID FindDlgAddListItem(
	_In_ HWND	hList,
	_In_ LPWSTR	ObjectName,
	_In_ LPWSTR	TypeName
	)
{
	LVITEMW				lvitem;
	int					index;

	RtlSecureZeroMemory(&lvitem, sizeof(lvitem));

	lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
	lvitem.iSubItem = 0;
	lvitem.pszText = ObjectName;
	lvitem.iItem = 0;
	lvitem.iImage = supGetObjectIndexByTypeName(TypeName);
	index = ListView_InsertItem(hList, &lvitem);

	lvitem.mask = LVIF_TEXT;
	lvitem.iSubItem = 1;
	lvitem.pszText = TypeName;
	lvitem.iItem = index;
	ListView_SetItem(hList, &lvitem);
}

/*
* FindDlgResize
*
* Purpose:
*
* FindDlg WM_SIZE handler, remember control position and move them according new window coordinates.
*
*/
VOID FindDlgResize(
	HWND hwndDlg
	)
{
	RECT r1, r2;
	HWND hwnd;
	POINT p0;
	GetClientRect(hwndDlg, &r2);

	if (sizes_init == 0) {
		sizes_init = 1;
		RtlSecureZeroMemory(&r1, sizeof(r1));
		GetWindowRect(GetDlgItem(hwndDlg, ID_SEARCH_GROUPBOXOPTIONS), &r1);
		dx1 = r2.right - (r1.right - r1.left);
		dx2 = r1.bottom - r1.top;
		RtlSecureZeroMemory(&r1, sizeof(r1));
		GetWindowRect(GetDlgItem(hwndDlg, ID_SEARCH_GROUPBOX), &r1);
		dx3 = r2.bottom - (r1.bottom - r1.top);

		RtlSecureZeroMemory(&r1, sizeof(r1));
		GetWindowRect(GetDlgItem(hwndDlg, ID_SEARCH_LIST), &r1);
		dx4 = r2.right - (r1.right - r1.left);
		dx5 = r2.bottom - (r1.bottom - r1.top);

		RtlSecureZeroMemory(&r1, sizeof(r1));
		GetWindowRect(GetDlgItem(hwndDlg, ID_SEARCH_NAME), &r1);
		dx6 = r2.right - (r1.right - r1.left);
		dx7 = r1.bottom - r1.top;

		RtlSecureZeroMemory(&r1, sizeof(r1));
		GetWindowRect(GetDlgItem(hwndDlg, ID_SEARCH_TYPE), &r1);
		p0.x = r1.left;
		p0.y = r1.top;
		ScreenToClient(hwndDlg, &p0);
		dx8 = r2.right - p0.x;
		dx9 = p0.y;

		RtlSecureZeroMemory(&r1, sizeof(r1));
		GetWindowRect(GetDlgItem(hwndDlg, ID_SEARCH_FIND), &r1);
		p0.x = r1.left;
		p0.y = r1.top;
		ScreenToClient(hwndDlg, &p0);
		dx10 = r2.right - p0.x;
		dx11 = p0.y;

		RtlSecureZeroMemory(&r1, sizeof(r1));
		GetWindowRect(GetDlgItem(hwndDlg, ID_SEARCH_TYPELABEL), &r1);
		p0.x = r1.left;
		p0.y = r1.top;
		ScreenToClient(hwndDlg, &p0);
		dx12 = r2.right - p0.x;
		dx13 = p0.y;
	}

	//resize groupbox search options
	hwnd = GetDlgItem(hwndDlg, ID_SEARCH_GROUPBOXOPTIONS);
	if (hwnd) {
		SetWindowPos(hwnd, 0, 0, 0, r2.right - dx1, dx2, SWP_NOMOVE | SWP_NOZORDER);
	}

	//resize groupbox results
	hwnd = GetDlgItem(hwndDlg, ID_SEARCH_GROUPBOX);
	if (hwnd) {
		SetWindowPos(hwnd, 0, 0, 0, r2.right - dx1, r2.bottom - dx3, SWP_NOMOVE | SWP_NOZORDER);
	}

	//resize listview
	hwnd = GetDlgItem(hwndDlg, ID_SEARCH_LIST);
	if (hwnd) {
		SetWindowPos(hwnd, 0, 0, 0, r2.right - dx4, r2.bottom - dx5, SWP_NOMOVE | SWP_NOZORDER);
	}

	//resize edit
	hwnd = GetDlgItem(hwndDlg, ID_SEARCH_NAME);
	if (hwnd) {
		SetWindowPos(hwnd, 0, 0, 0, r2.right - dx6, dx7, SWP_NOMOVE | SWP_NOZORDER);
	}

	//resize combobox
	hwnd = GetDlgItem(hwndDlg, ID_SEARCH_TYPE);
	if (hwnd) {
		SetWindowPos(hwnd, 0, r2.right - dx8, dx9, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
	}

	hwnd = GetDlgItem(hwndDlg, ID_SEARCH_FIND);
	if (hwnd) {
		SetWindowPos(hwnd, 0, r2.right - dx10, dx11, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
	}

	//resize Type label
	hwnd = GetDlgItem(hwndDlg, ID_SEARCH_TYPELABEL);
	if (hwnd) {
		SetWindowPos(hwnd, 0, r2.right - dx12, dx13, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
	}

	RedrawWindow(hwndDlg, NULL, 0, RDW_ERASE | RDW_INVALIDATE | RDW_ERASENOW);
}

/*
* FindDlgHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for FindDlg listview.
*
*/
VOID FindDlgHandleNotify(
	LPNMLISTVIEW	nhdr
	)
{
	LPWSTR			lpItemText;
	LVCOLUMNW		col;
	INT				c, k;

	if (nhdr == NULL)
		return;

	if (nhdr->hdr.idFrom != ID_SEARCH_LIST)
		return;

	switch (nhdr->hdr.code) {

	case LVN_ITEMCHANGED:
		if (!(nhdr->uNewState & LVIS_SELECTED))
			break;
		
		lpItemText = supGetItemText(nhdr->hdr.hwndFrom, nhdr->iItem, 0, NULL);
		if (lpItemText) {
			ListToObject(lpItemText);
			HeapFree(GetProcessHeap(), 0, lpItemText);
		}
		break;

	case LVN_COLUMNCLICK:
		bFindDlgSortInverse = !bFindDlgSortInverse;
		FindDlgSortColumn = ((NMLISTVIEW *)nhdr)->iSubItem;
		ListView_SortItemsEx(FindDlgList, &FindDlgCompareFunc, FindDlgSortColumn);

		RtlSecureZeroMemory(&col, sizeof(col));
		col.mask = LVCF_IMAGE;
		col.iImage = -1;

		for (c = 0; c < 2; c++)
			ListView_SetColumn(FindDlgList, c, &col);

		k = ImageList_GetImageCount(ListViewImages);
		if (bFindDlgSortInverse)
			col.iImage = k - 2;
		else
			col.iImage = k - 1;

		ListView_SetColumn(FindDlgList, ((NMLISTVIEW *)nhdr)->iSubItem, &col);
		break;

	default:
		break;
	}
}

/*
* FindDlgProc
*
* Purpose:
*
* Find Dialog window procedure.
*
*/
INT_PTR CALLBACK FindDlgProc(
	_In_  HWND hwndDlg,
	_In_  UINT uMsg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
	)
{
	WCHAR			search_string[MAX_PATH + 1], type_name[MAX_PATH + 1];
	LPWSTR			pnamestr = (LPWSTR)search_string, ptypestr = (LPWSTR)type_name;
	PFO_LIST_ITEM	flist, plist;
	ULONG			cci;
	HANDLE			hIcon = NULL;
	LPNMLISTVIEW	nhdr = (LPNMLISTVIEW)lParam;

	switch (uMsg) {
	case WM_NOTIFY:
		FindDlgHandleNotify(nhdr);
		break;

	case WM_GETMINMAXINFO:
		if (lParam) {
			((PMINMAXINFO)lParam)->ptMinTrackSize.x = 548;
			((PMINMAXINFO)lParam)->ptMinTrackSize.y = 230;
		}
		break;

	case WM_INITDIALOG:
		supCenterWindow(hwndDlg);
		FindDlgResize(hwndDlg);
		hIcon = LoadImage(g_hInstance, MAKEINTRESOURCE(IDI_ICON_MAIN), IMAGE_ICON, 0, 0, LR_SHARED);
		if (hIcon) {
			SetClassLongPtr(hwndDlg, GCLP_HICON, (LONG_PTR)hIcon);
			DestroyIcon(hIcon);
		}
		break;

	case WM_SIZE:
		FindDlgResize(hwndDlg);
		break;

	case WM_CLOSE:
		DestroyWindow(hwndDlg);
		FindDialog = NULL;
		return TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDCANCEL) {
			DestroyWindow(hwndDlg);
			FindDialog = NULL;
			return TRUE;
		}

		if (LOWORD(wParam) == ID_SEARCH_FIND) {

			supSetWaitCursor(TRUE);
			EnableWindow(GetDlgItem(hwndDlg, ID_SEARCH_FIND), FALSE);

			ListView_DeleteAllItems(FindDlgList);
			RtlSecureZeroMemory(&search_string, sizeof(search_string));
			RtlSecureZeroMemory(&type_name, sizeof(type_name));
			SendMessageW(GetDlgItem(hwndDlg, ID_SEARCH_NAME), WM_GETTEXT, MAX_PATH, (LPARAM)&search_string);
			SendMessageW(GetDlgItem(hwndDlg, ID_SEARCH_TYPE), WM_GETTEXT, MAX_PATH, (LPARAM)&type_name);
			flist = NULL;

			if (search_string[0] == 0)
				pnamestr = NULL;
			if (type_name[0] == '*')
				ptypestr = 0;

			FindObject(L"\\", pnamestr, ptypestr, &flist);

			cci = 0;
			while (flist != NULL) {
				FindDlgAddListItem(FindDlgList, flist->ObjectName, flist->ObjectType);
				plist = flist->Prev;
				HeapFree(GetProcessHeap(), 0, flist);
				flist = plist;
				cci++;
			}

			ultostrW(cci, search_string);
			_strcatW(search_string, L" Object(s) found");
			SendMessageW(GetDlgItem(hwndDlg, ID_SEARCH_GROUPBOX), WM_SETTEXT, 0, (LPARAM)search_string);

			ListView_SortItemsEx(FindDlgList, &FindDlgCompareFunc, FindDlgSortColumn);

			supSetWaitCursor(FALSE);
			EnableWindow(GetDlgItem(hwndDlg, ID_SEARCH_FIND), TRUE);
		}

		break;
	}
	return FALSE;
}

/*
* FindDlgAddTypes
*
* Purpose:
*
* Enumerate object types and fill combobox with them.
*
* Elevation required.
*
*/
VOID FindDlgAddTypes(
	HWND hwnd
	)
{
	OBJECT_ATTRIBUTES	objattr;
	UNICODE_STRING		objname;
	HANDLE				hDirectory = NULL;
	NTSTATUS			status;
	ULONG				ctx, rlen;
	BOOL				cond = TRUE;

	POBJECT_DIRECTORY_INFORMATION	objinf;

	HWND hComboBox = GetDlgItem(hwnd, ID_SEARCH_TYPE);
	if (hComboBox) {

		SendMessage(hComboBox, CB_RESETCONTENT, (WPARAM)0, (LPARAM)0);

		RtlSecureZeroMemory(&objname, sizeof(objname));
		RtlInitUnicodeString(&objname, L"\\ObjectTypes");
		InitializeObjectAttributes(&objattr, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);
		status = NtOpenDirectoryObject(&hDirectory, FILE_LIST_DIRECTORY, &objattr);

		if (NT_SUCCESS(status)) {

			ctx = 0;
			do {
				rlen = 0;
				status = NtQueryDirectoryObject(hDirectory, NULL, 0, TRUE, FALSE, &ctx, &rlen);
				if (status != STATUS_BUFFER_TOO_SMALL)
					break;

				objinf = HeapAlloc(GetProcessHeap(), 0, rlen);
				if (objinf == NULL)
					break;

				RtlSecureZeroMemory(objinf, rlen);
				status = NtQueryDirectoryObject(hDirectory, objinf, rlen, TRUE, FALSE, &ctx, &rlen);
				if (!NT_SUCCESS(status)) {
					HeapFree(GetProcessHeap(), 0, objinf);
					break;
				}

				SendMessage(hComboBox, CB_ADDSTRING, (WPARAM)0, (LPARAM)objinf->Name.Buffer);

				HeapFree(GetProcessHeap(), 0, objinf);
			} while (cond);

			NtClose(hDirectory);
		}
		SendMessage(hComboBox, CB_ADDSTRING, (WPARAM)0, (LPARAM)L"*");
		SendMessage(hComboBox, CB_SETCURSEL, (WPARAM)0, (LPARAM)0);
	}
}

/*
* FindDlgInit
*
* Purpose:
*
* Initialize Find Dialog.
*
*/
VOID FindDlgInit(
	VOID
	)
{
	LVCOLUMNW	col;

	//do not allow second copy
	if (FindDialog)
		return;

	FindDialog = CreateDialogParam(g_hInstance, MAKEINTRESOURCE(IDD_DIALOG_SEARCH), MainWindow, &FindDlgProc, 0);
	if (FindDialog == NULL)
		return;

	FindDlgList = GetDlgItem(FindDialog, ID_SEARCH_LIST);
	if (FindDlgList) {
		bFindDlgSortInverse = FALSE;	
		ListView_SetImageList(FindDlgList, ListViewImages, LVSIL_SMALL);
		ListView_SetExtendedListViewStyle(FindDlgList, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

		RtlSecureZeroMemory(&col, sizeof(col));
		col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER | LVCF_IMAGE;
		col.iSubItem = 1;
		col.pszText = L"Name";
		col.fmt = LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT;
		col.iOrder = 0;
		col.iImage = ImageList_GetImageCount(ListViewImages) - 1;
		col.cx = 300;
		ListView_InsertColumn(FindDlgList, 1, &col);

		col.iSubItem = 2;
		col.pszText = L"Type";
		col.iOrder = 1;
		col.iImage = -1;
		col.cx = 100;
		ListView_InsertColumn(FindDlgList, 2, &col);
	}
	FindDlgAddTypes(FindDialog);
}