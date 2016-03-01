/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2016
*
*  TITLE:       EXTRASUSD.C
*
*  VERSION:     1.41
*
*  DATE:        01 Mar 2016
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "extras.h"
#include "propDlg.h"
#include "propObjectDump.h"
#include "extrasUSD.h"

EXTRASCONTEXT UsdDlgContext;

/*
* UsdDumpSharedRegion
*
* Purpose:
*
* Display dump of SharedData.
*
*/
VOID UsdDumpSharedRegion(
	_In_ HWND hwndParent
	)
{
	BOOL                  bCond = FALSE;
	INT                   i;
	DWORD                 mask;
	HWND                  UsdTreeList;
	ATOM                  UsdTreeListAtom;

	NTSTATUS              status;
	SIZE_T                memIO = 0x1000;
	PKUSER_SHARED_DATA    pData = NULL;

	HTREEITEM             h_tviRootItem, h_tviSubItem;
	LPWSTR                lpType;
	TL_SUBITEMS_FIXED     subitems;
	WCHAR                 szValue[MAX_PATH + 1];

	do {

		//Allocate temp buffer for UserSharedData copy
		pData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, memIO);
		if (pData == NULL) {
			break;
		}

		//Attempt to copy UserSharedData
		status = NtReadVirtualMemory(GetCurrentProcess(), (PVOID)MM_SHARED_USER_DATA_VA, pData, memIO, &memIO);
		if (!NT_SUCCESS(status)) {
			break;
		}

		UsdTreeList = 0;
		UsdTreeListAtom = 0;
		if (!supInitTreeListForDump(hwndParent, &UsdTreeListAtom, &UsdTreeList)) {
			break;
		}

		//
		//KUSER_SHARED_DATA
		//

		h_tviRootItem = TreeListAddItem(UsdTreeList, NULL, TVIF_TEXT | TVIF_STATE, TVIS_EXPANDED,
			TVIS_EXPANDED, TEXT("KUSER_SHARED_DATA"), NULL);
		if (h_tviRootItem == NULL) {
			break;
		}

		//NtSystemRoot
		RtlSecureZeroMemory(&subitems, sizeof(subitems));
		subitems.Text[0] = pData->NtSystemRoot;
		subitems.Count = 1;
		TreeListAddItem(UsdTreeList, h_tviRootItem, TVIF_TEXT | TVIF_STATE, 0, 0, TEXT("NtSystemRoot"), &subitems);

		//NtProductType
		switch (pData->NtProductType) {
		case NtProductWinNt:
			lpType = TEXT("NtProductWinNt");
			break;
		case NtProductLanManNt:
			lpType = TEXT("NtProductLanManNt");
			break;
		case NtProductServer:
			lpType = TEXT("NtProductServer");
			break;	
		default:
			lpType = T_UnknownType;
			break;
		}
		ObDumpUlong(UsdTreeList, h_tviRootItem, TEXT("NtProductType"), lpType, pData->NtProductType, FALSE, FALSE, 0, 0);
		ObDumpByte(UsdTreeList, h_tviRootItem, TEXT("ProductTypeIsValid"), NULL, pData->ProductTypeIsValid, 0, 0, TRUE);
		
		//Version
		ObDumpUlong(UsdTreeList, h_tviRootItem, TEXT("NtMajorVersion"), NULL, pData->NtMajorVersion, FALSE, FALSE, 0, 0);
		ObDumpUlong(UsdTreeList, h_tviRootItem, TEXT("NtMinorVersion"), NULL, pData->NtMinorVersion, FALSE, FALSE, 0, 0);

		//ProcessorFeatures
		h_tviSubItem = TreeListAddItem(UsdTreeList, h_tviRootItem, TVIF_TEXT | TVIF_STATE, 0, 0, TEXT("ProcessorFeatures"), NULL);
		if (h_tviSubItem) {
			for (i = 0; i < PROCESSOR_FEATURE_MAX; i++) {
				if (pData->ProcessorFeatures[i]) {
					if (i > 32) {
						lpType = T_Unknown;
					}
					else {
						lpType = T_PROCESSOR_FEATURES[i];
					}
					RtlSecureZeroMemory(&subitems, sizeof(subitems));
					RtlSecureZeroMemory(&szValue, sizeof(szValue));
					itostr_w(i, szValue);
					subitems.Text[0] = szValue;
					subitems.Text[1] = lpType;
					subitems.Count = 2;
					TreeListAddItem(UsdTreeList, h_tviSubItem, TVIF_TEXT | TVIF_STATE, 0, 0, NULL, &subitems);
				}
			}
		}

		//AlternativeArchitecture
		switch (pData->AlternativeArchitecture) {
		case StandardDesign:
			lpType = TEXT("StandardDesign");
			break;
		case NEC98x86:
			lpType = TEXT("NEC98x86");
			break;
		default: 
			lpType = T_UnknownType;
			break;
		}
		ObDumpUlong(UsdTreeList, h_tviRootItem, TEXT("AlternativeArchitecture"), lpType, pData->AlternativeArchitecture, FALSE, FALSE, 0, 0);

		//SuiteMask
		RtlSecureZeroMemory(&subitems, sizeof(subitems));
		RtlSecureZeroMemory(&szValue, sizeof(szValue));
		szValue[0] = L'0';
		szValue[1] = L'x';
		ultohex_w(pData->SuiteMask, &szValue[2]);
		subitems.Text[0] = szValue;
		subitems.Count = 1;
		h_tviSubItem = TreeListAddItem(UsdTreeList, h_tviRootItem, TVIF_TEXT | TVIF_STATE, 0, 0, L"SuiteMask", &subitems);
		if (h_tviSubItem) {
			mask = pData->SuiteMask;
			for (i = 0; i < MAX_KNOWN_SUITEMASKS; i++) {
				if (mask & SuiteMasks[i].dwValue) {
					RtlSecureZeroMemory(&subitems, sizeof(subitems));
					RtlSecureZeroMemory(&szValue, sizeof(szValue));
					szValue[0] = L'0';
					szValue[1] = L'x';
					ultohex_w(SuiteMasks[i].dwValue, &szValue[2]);
					subitems.Text[0] = szValue;
					subitems.Text[1] = SuiteMasks[i].lpDescription;
					subitems.Count = 2;
					TreeListAddItem(UsdTreeList, h_tviSubItem, TVIF_TEXT | TVIF_STATE, 0, 0, NULL, &subitems);
					mask &= ~SuiteMasks[i].dwValue;
				}
			}
		}

		//KdDebuggerEnabled
		ObDumpByte(UsdTreeList, h_tviRootItem, TEXT("KdDebuggerEnabled"), NULL, pData->KdDebuggerEnabled, 0, 0, TRUE);

		//MitigationPolicies
		ObDumpByte(UsdTreeList, h_tviRootItem, TEXT("MitigationPolicies"), NULL, pData->MitigationPolicies, 0, 0, FALSE);

		//SafeBootMode
		ObDumpByte(UsdTreeList, h_tviRootItem, TEXT("SafeBootMode"), NULL, pData->SafeBootMode, 0, 0, TRUE);

		//SharedDataFlags
		RtlSecureZeroMemory(&subitems, sizeof(subitems));
		RtlSecureZeroMemory(&szValue, sizeof(szValue));
		szValue[0] = L'0';
		szValue[1] = L'x';
		ultohex_w(pData->SharedDataFlags, &szValue[2]);
		subitems.Text[0] = szValue;
		subitems.Count = 1;
		h_tviSubItem = TreeListAddItem(UsdTreeList, h_tviRootItem, TVIF_TEXT | TVIF_STATE, 0, 0, TEXT("SharedDataFlags"), &subitems);
		if (h_tviSubItem) {
			for (i = 0; i < 9; i++) {
				if (GET_BIT(pData->SharedDataFlags, i)) {
					RtlSecureZeroMemory(&subitems, sizeof(subitems));
					RtlSecureZeroMemory(&szValue, sizeof(szValue));
					_strcpy_w(szValue, L"BitPos: ");
					itostr_w(i, _strend_w(szValue));
					subitems.Text[0] = szValue;
					subitems.Text[1] = (LPTSTR)T_SharedDataFlags[i];
					subitems.Count = 2;
					TreeListAddItem(UsdTreeList, h_tviSubItem, TVIF_TEXT | TVIF_STATE, 0, 0, NULL, &subitems);
				}
			}
		}

	} while (bCond);

	if (pData) {
		HeapFree(GetProcessHeap(), 0, pData);
	}
}

/*
* UsdDialogProc
*
* Purpose:
*
* Usd Dialog Procedure
*
*/
INT_PTR CALLBACK UsdDialogProc(
	_In_  HWND hwndDlg,
	_In_  UINT uMsg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
	)
{
	UNREFERENCED_PARAMETER(lParam);

	switch (uMsg) {

	case WM_INITDIALOG:
		supCenterWindow(hwndDlg);
		break;

	case WM_CLOSE:
		DestroyWindow(hwndDlg);
		g_wobjDialogs[WOBJ_USDDLG_IDX] = NULL;
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
* extrasCreateUsdDialog
*
* Purpose:
*
* Create and initialize Usd Dialog.
*
*/
VOID extrasCreateUsdDialog(
	_In_ HWND hwndParent
	)
{
	//allow only one dialog
	if (g_wobjDialogs[WOBJ_USDDLG_IDX]) {
		SetActiveWindow(g_wobjDialogs[WOBJ_USDDLG_IDX]);
		return;
	}

	RtlSecureZeroMemory(&UsdDlgContext, sizeof(UsdDlgContext));
	UsdDlgContext.hwndDlg = CreateDialogParam(g_hInstance, MAKEINTRESOURCE(IDD_DIALOG_USD),
		hwndParent, &UsdDialogProc, 0);

	if (UsdDlgContext.hwndDlg == NULL) {
		return;
	}

	g_wobjDialogs[WOBJ_USDDLG_IDX] = UsdDlgContext.hwndDlg;

	UsdDumpSharedRegion(UsdDlgContext.hwndDlg);
}
