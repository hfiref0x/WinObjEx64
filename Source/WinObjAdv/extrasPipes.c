/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       EXTRASPIPES.C
*
*  VERSION:     1.30
*
*  DATE:        10 Aug 2015
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "propDlg.h"
#include "propSecurity.h"

//named pipes root
#define T_DEVICE_NAMED_PIPE L"\\Device\\NamedPipe\\"

//maximum number of possible pages
#define EXTRAS_MAX_PAGE 2
HPROPSHEETPAGE epsp[EXTRAS_MAX_PAGE];//pipe, security

static HWND PipeDialog = NULL;

HWND PipeDlgList = NULL;
BOOL bPipeDlgSortInverse = FALSE;
HIMAGELIST PipeImageList = NULL;

/*
* PipeDisplayError
*
* Purpose:
*
* Display last Win32 error.
*
*/
VOID PipeDisplayError(
	HWND hwndDlg
	)
{
	DWORD dwLastError;
	WCHAR szBuffer[MAX_PATH + 1];

	dwLastError = GetLastError();
	ShowWindow(GetDlgItem(hwndDlg, ID_PIPE_QUERYFAIL), SW_SHOW);

	RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
	_strcpy(szBuffer, L"Cannot open pipe because: ");
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, dwLastError,
		0, _strend(szBuffer), MAX_PATH, NULL);
	SetDlgItemText(hwndDlg, ID_PIPE_QUERYFAIL, szBuffer);
}

/*
* PipeCreateFullName
*
* Purpose:
*
* Create complete pipe name.
* Caller responsible for cleanup with HeapFree after use.
*
*/
LPWSTR PipeCreateFullName(
	_In_ LPWSTR lpObjectName
	)
{
	LPWSTR	lpFullName;
	SIZE_T	sz;

	if (lpObjectName == NULL) {
		return NULL;
	}

	sz = (_strlen(T_DEVICE_NAMED_PIPE) + _strlen(lpObjectName)) * sizeof(WCHAR) +
		sizeof(UNICODE_NULL);
	lpFullName = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
	if (lpFullName == NULL) {
		return lpFullName;
	}

	_strcpy(lpFullName, T_DEVICE_NAMED_PIPE);
	_strcat(lpFullName, lpObjectName);
	return lpFullName;
}

/*
* PipeOpenObjectMethod
*
* Purpose:
*
* Used by Security Editor to access object by name.
*
*/
BOOL CALLBACK PipeOpenObjectMethod(
	_In_	PROP_OBJECT_INFO *Context,
	_Inout_ PHANDLE	phObject,
	_In_	ACCESS_MASK	DesiredAccess
	)
{
	BOOL				bResult = FALSE;
	HANDLE				hObject;
	NTSTATUS			status;
	OBJECT_ATTRIBUTES	obja;
	UNICODE_STRING		uStr;
	IO_STATUS_BLOCK		iost;

	if (
		(Context == NULL) ||
		(phObject == NULL)
		)
	{
		return bResult;
	}
	*phObject = NULL;

	RtlSecureZeroMemory(&uStr, sizeof(uStr));
	RtlInitUnicodeString(&uStr, Context->lpCurrentObjectPath);
	InitializeObjectAttributes(&obja, &uStr, OBJ_CASE_INSENSITIVE, NULL, NULL);
	hObject = NULL;
	status = NtOpenFile(&hObject, DesiredAccess, &obja, &iost,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0);

	if (NT_SUCCESS(status)) {
		*phObject = hObject;
	}
	SetLastError(RtlNtStatusToDosError(status));
	bResult = (NT_SUCCESS(status) && (hObject != NULL));
	return bResult;
}

/*
* PipeQueryInfo
*
* Purpose:
*
* Query basic info about pipe.
*
*/
VOID PipeQueryInfo(
	PROP_OBJECT_INFO *Context,
	HWND hwndDlg
	)
{
	LPWSTR						lpType;
	HANDLE						hPipe;
	NTSTATUS					status;
	WCHAR						szBuffer[MAX_PATH];
	IO_STATUS_BLOCK				iost;
	FILE_PIPE_LOCAL_INFORMATION fpli;

	//validate context
	if (Context == NULL) {
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		PipeDisplayError(hwndDlg);
		return;
	}
	if (
		(Context->lpObjectName == NULL) ||
		(Context->lpCurrentObjectPath == NULL)
		)
	{
		SetLastError(ERROR_OBJECT_NOT_FOUND);
		PipeDisplayError(hwndDlg);
		return;
	}

	SetDlgItemText(hwndDlg, ID_PIPE_FULLPATH, Context->lpCurrentObjectPath);

	//open pipe
	hPipe = NULL;
	if (!PipeOpenObjectMethod(Context, &hPipe, GENERIC_READ)) {
		//on error display last win32 error
		PipeDisplayError(hwndDlg);
		return;
	}

	RtlSecureZeroMemory(&fpli, sizeof(fpli));
	status = NtQueryInformationFile(hPipe, &iost, &fpli, sizeof(fpli), FilePipeLocalInformation);
	if (NT_SUCCESS(status)) {

		//Type
		lpType = L"?";
		switch (fpli.NamedPipeType) {
		case FILE_PIPE_BYTE_STREAM_TYPE:
			lpType = L"Byte stream";
			break;
		case FILE_PIPE_MESSAGE_TYPE:
			lpType = L"Message";
			break;
		}
		SetDlgItemText(hwndDlg, ID_PIPE_TYPEMODE, lpType);

		//AccessMode
		lpType = L"?";
		switch (fpli.NamedPipeConfiguration) {
		case FILE_PIPE_INBOUND:
			lpType = L"Inbound";
			break;
		case FILE_PIPE_OUTBOUND:
			lpType = L"Outbound";
			break;
		case FILE_PIPE_FULL_DUPLEX:
			lpType = L"Duplex";
			break;
		}
		SetDlgItemText(hwndDlg, ID_PIPE_ACCESSMODE, lpType);

		//CurrentInstances
		RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
		ultostr(fpli.CurrentInstances, szBuffer);
		SetDlgItemText(hwndDlg, ID_PIPE_CURINSTANCES, szBuffer);

		//MaximumInstances
		RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
		if (fpli.MaximumInstances == MAXDWORD) {
			_strcpy(szBuffer, L"Unlimited");
		}
		else {
			ultostr(fpli.MaximumInstances, szBuffer);
		}
		SetDlgItemText(hwndDlg, ID_PIPE_MAXINSTANCES, szBuffer);

		//InboundQuota
		RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
		ultostr(fpli.InboundQuota, szBuffer);
		SetDlgItemText(hwndDlg, ID_PIPE_INBUFFER, szBuffer);

		//OutboundQuota
		RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
		ultostr(fpli.OutboundQuota, szBuffer);
		SetDlgItemText(hwndDlg, ID_PIPE_OUTBUFFER, szBuffer);

		//WriteQuotaAvailable
		RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
		ultostr(fpli.WriteQuotaAvailable, szBuffer);
		SetDlgItemText(hwndDlg, ID_PIPE_WRITEQUOTAAVAIL, szBuffer);
	}
	else {
		//show detail on query error
		SetLastError(RtlNtStatusToDosError(status));
		PipeDisplayError(hwndDlg);
	}
	NtClose(hPipe);
}

/*
* PipeTypeDialogProc
*
* Purpose:
*
* Pipe Properties Dialog Procedure
*
*/
INT_PTR CALLBACK PipeTypeDialogProc(
	_In_  HWND hwndDlg,
	_In_  UINT uMsg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
	)
{
	HDC hDc;
	PAINTSTRUCT Paint;
	PROPSHEETPAGE *pSheet = NULL;
	PROP_OBJECT_INFO *Context = NULL;

	switch (uMsg) {

	case WM_INITDIALOG:
		pSheet = (PROPSHEETPAGE *)lParam;
		if (pSheet) {
			SetProp(hwndDlg, T_PROPCONTEXT, (HANDLE)pSheet->lParam);
		}
		return 1;
		break;

	case WM_SHOWWINDOW:
		if (wParam) {
			Context = GetProp(hwndDlg, T_PROPCONTEXT);
			if (Context) {
				PipeQueryInfo(Context, hwndDlg);
			}
		}
		return 1;
		break;

	case WM_PAINT:
		hDc = BeginPaint(hwndDlg, &Paint);
		if (hDc) {
			ImageList_Draw(PipeImageList, 0, hDc, 24, 34, ILD_NORMAL | ILD_TRANSPARENT);
			EndPaint(hwndDlg, &Paint);
		}
		return 1;
		break;

	case WM_DESTROY:
		RemoveProp(hwndDlg, T_PROPCONTEXT);
		break;

	}
	return 0;
}

/*
* PipeDlgShowProperties
*
* Purpose:
*
* Show properties dialog for selected pipe.
* Because of Pipe special case we cannot use propCreateDialog.
*
*/
VOID PipeDlgShowProperties(
	_In_ INT iItem
	)
{
	INT					nPages = 0;
	PROP_OBJECT_INFO	*Context;
	HPROPSHEETPAGE		SecurityPage = NULL;
	PROPSHEETPAGE		Page;
	PROPSHEETHEADER		PropHeader;
	WCHAR				szCaption[MAX_PATH];

	Context = propContextCreate(NULL, NULL, NULL, NULL);
	if (Context == NULL) {
		return;
	}

	Context->lpObjectName = supGetItemText(PipeDlgList, iItem, 0, NULL);
	Context->lpCurrentObjectPath = PipeCreateFullName(Context->lpObjectName);

	//
	//Create Pipe Page
	//
	RtlSecureZeroMemory(&Page, sizeof(Page));
	Page.dwSize = sizeof(PROPSHEETPAGE);
	Page.dwFlags = PSP_DEFAULT | PSP_USETITLE;
	Page.hInstance = g_hInstance;
	Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_PIPE);
	Page.pfnDlgProc = PipeTypeDialogProc;
	Page.pszTitle = L"Pipe";
	Page.lParam = (LPARAM)Context;
	epsp[nPages++] = CreatePropertySheetPage(&Page);

	//
	//Create Security Dialog if available
	//
	SecurityPage = propSecurityCreatePage(
		Context,
		(POPENOBJECTMETHOD)&PipeOpenObjectMethod,
		NULL, //use default close method
		SI_EDIT_AUDITS | SI_EDIT_OWNER | SI_EDIT_PERMS |
		SI_ADVANCED | SI_NO_ACL_PROTECT | SI_NO_TREE_APPLY |
		SI_PAGE_TITLE
		);
	if (SecurityPage != NULL) {
		epsp[nPages++] = SecurityPage;
	}

	//
	//Create property sheet
	//
	_strcpy(szCaption, L"Pipe Properties");
	RtlSecureZeroMemory(&PropHeader, sizeof(PropHeader));
	PropHeader.dwSize = sizeof(PropHeader);
	PropHeader.phpage = epsp;
	PropHeader.nPages = nPages;
	PropHeader.dwFlags = PSH_DEFAULT | PSH_NOCONTEXTHELP;
	PropHeader.nStartPage = 0;
	PropHeader.hwndParent = PipeDialog;
	PropHeader.hInstance = g_hInstance;
	PropHeader.pszCaption = szCaption;

	PropertySheet(&PropHeader);
	propContextDestroy(Context);
}

/*
* PipeDlgCompareFunc
*
* Purpose:
*
* Pipe Dialog listview comparer function.
*
*/
INT CALLBACK PipeDlgCompareFunc(
	_In_ LPARAM lParam1,
	_In_ LPARAM lParam2,
	_In_ LPARAM lParamSort
	)
{
	LPWSTR lpItem1, lpItem2;
	INT nResult = 0;

	lpItem1 = supGetItemText(PipeDlgList, (INT)lParam1, (INT)lParamSort, NULL);
	lpItem2 = supGetItemText(PipeDlgList, (INT)lParam2, (INT)lParamSort, NULL);

	if ((lpItem1 == NULL) && (lpItem2 == NULL)) {
		nResult = 0;
		goto Done;
	}
	if ((lpItem1 == NULL) && (lpItem2 != NULL)) {
		nResult = (bPipeDlgSortInverse) ? 1 : -1;
		goto Done;
	}
	if ((lpItem2 == NULL) && (lpItem1 != NULL)) {
		nResult = (bPipeDlgSortInverse) ? -1 : 1;
		goto Done;
	}

	if (bPipeDlgSortInverse)
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

/*
* PipeDlgHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for Pipe Dialog listview.
*
*/
VOID PipeDlgHandleNotify(
	LPARAM lParam
	)
{
	LVCOLUMNW		col;
	LPNMHDR			nhdr = (LPNMHDR)lParam;

	if (nhdr == NULL)
		return;

	if (nhdr->idFrom != ID_PIPESLIST)
		return;

	switch (nhdr->code) {

	case LVN_COLUMNCLICK:
		bPipeDlgSortInverse = !bPipeDlgSortInverse;
		ListView_SortItemsEx(PipeDlgList, &PipeDlgCompareFunc, 0);

		RtlSecureZeroMemory(&col, sizeof(col));
		col.mask = LVCF_IMAGE;
		col.iImage = -1;

		ListView_SetColumn(PipeDlgList, 0, &col);

		if (bPipeDlgSortInverse)
			col.iImage = 1;
		else
			col.iImage = 2;

		ListView_SetColumn(PipeDlgList, 0, &col);
		break;

	case NM_DBLCLK:
		PipeDlgShowProperties(((LPNMITEMACTIVATE)lParam)->iItem);
		break;

	default:
		break;
	}
}

/*
* PipeDlgQueryInfo
*
* Purpose:
*
* List pipes from pipe device.
*
*/
VOID PipeDlgQueryInfo(
	)
{
	BOOL						cond = FALSE, cond2 = TRUE;
	BOOLEAN						bRestartScan;
	HANDLE						hObject = NULL;
	FILE_DIRECTORY_INFORMATION	*DirectoryInfo = NULL;
	NTSTATUS					status;
	OBJECT_ATTRIBUTES			obja;
	UNICODE_STRING				uStr;
	IO_STATUS_BLOCK				iost;
	LVITEMW						lvitem;
	INT							c;

	do {

		RtlSecureZeroMemory(&uStr, sizeof(uStr));
		RtlInitUnicodeString(&uStr, T_DEVICE_NAMED_PIPE);
		InitializeObjectAttributes(&obja, &uStr, OBJ_CASE_INSENSITIVE, NULL, NULL);
		status = NtOpenFile(&hObject, FILE_LIST_DIRECTORY, &obja, &iost,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SUPERSEDE);
		if (!NT_SUCCESS(status)) {
			break;
		}

		DirectoryInfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000);
		if (DirectoryInfo == NULL) {
			break;
		}

		c = 0;
		bRestartScan = TRUE;
		while (cond2) {

			RtlSecureZeroMemory(&iost, sizeof(iost));

			status = NtQueryDirectoryFile(hObject, NULL, NULL, NULL, &iost,
				DirectoryInfo, 0x1000, FileDirectoryInformation,
				TRUE, //ReturnSingleEntry
				NULL,
				bRestartScan //RestartScan
				);

			if (
				(!NT_SUCCESS(status)) ||
				(!NT_SUCCESS(iost.Status)) ||
				(iost.Information == 0)
				)
			{
				break;
			}

			//Name
			RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
			lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
			lvitem.iImage = 0;
			lvitem.iSubItem = 0;
			lvitem.pszText = DirectoryInfo->FileName;
			lvitem.iItem = MAXINT;
			ListView_InsertItem(PipeDlgList, &lvitem);
			bRestartScan = FALSE;
			RtlSecureZeroMemory(DirectoryInfo, 0x1000);

			c++;
			if (c > 0x10000) {//its a trap
				break;
			}
		}

	} while (cond);

	if (DirectoryInfo != NULL) {
		HeapFree(GetProcessHeap(), 0, DirectoryInfo);
	}

	if (hObject) {
		NtClose(hObject);
	}
}

/*
* PipeDlgProc
*
* Purpose:
*
* Pipe Dialog window procedure.
*
*/
INT_PTR CALLBACK PipeDlgProc(
	_In_  HWND hwndDlg,
	_In_  UINT uMsg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
	)
{
	switch (uMsg) {
	case WM_NOTIFY:
		PipeDlgHandleNotify(lParam);
		break;

	case WM_INITDIALOG:
		supCenterWindow(hwndDlg);
		break;

	case WM_CLOSE:
		DestroyWindow(hwndDlg);
		PipeDialog = NULL;
		g_wobjDialogs[WOBJ_PIPEDLG_IDX] = NULL;
		ImageList_Destroy(PipeImageList);
		PipeImageList = NULL;
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
* extrasCreatePipeDialog
*
* Purpose:
*
* Create and initialize Pipe Dialog.
*
*/
VOID extrasCreatePipeDialog(
	_In_ HWND hwndParent
	)
{
	LVCOLUMNW	col;
	HICON		hIcon;

	//allow only one dialog
	if (g_wobjDialogs[WOBJ_PIPEDLG_IDX]) {
		return;
	}

	PipeDialog = CreateDialogParam(g_hInstance, MAKEINTRESOURCE(IDD_DIALOG_PIPES),
		hwndParent, &PipeDlgProc, 0);

	if (PipeDialog == NULL) {
		return;
	}
	g_wobjDialogs[WOBJ_PIPEDLG_IDX] = PipeDialog;

	PipeDlgList = GetDlgItem(PipeDialog, ID_PIPESLIST);
	if (PipeDlgList) {
		PipeImageList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 42, 8);
		if (PipeImageList) {

			//set default app icon
			hIcon = LoadImage(g_hInstance, MAKEINTRESOURCE(IDI_ICON_PIPE), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
			if (hIcon) {
				ImageList_ReplaceIcon(PipeImageList, -1, hIcon);
				DestroyIcon(hIcon);
			}
			//sort images
			hIcon = LoadImage(g_hInstance, MAKEINTRESOURCE(IDI_ICON_SORTUP), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
			if (hIcon) {
				ImageList_ReplaceIcon(PipeImageList, -1, hIcon);
				DestroyIcon(hIcon);
			}
			hIcon = LoadImage(g_hInstance, MAKEINTRESOURCE(IDI_ICON_SORTDOWN), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
			if (hIcon) {
				ImageList_ReplaceIcon(PipeImageList, -1, hIcon);
				DestroyIcon(hIcon);
			}
			ListView_SetImageList(PipeDlgList, PipeImageList, LVSIL_SMALL);
		}

		ListView_SetExtendedListViewStyle(PipeDlgList,
			LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

		RtlSecureZeroMemory(&col, sizeof(col));
		col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER | LVCF_IMAGE;
		col.iSubItem = 1;
		col.pszText = L"Name";
		col.fmt = LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT;
		col.iOrder = 0;
		col.iImage = 2;
		col.cx = 500;
		ListView_InsertColumn(PipeDlgList, 1, &col);

		PipeDlgQueryInfo();
		bPipeDlgSortInverse = FALSE;
		ListView_SortItemsEx(PipeDlgList, &PipeDlgCompareFunc, 0);
	}
}
