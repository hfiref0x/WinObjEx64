/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       EXTRASUSD.C
*
*  VERSION:     1.20
*
*  DATE:        23 July 2015
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "extrasUSD.h"
#include "propDlg.h"
#include "propObjectDump.h"

#define MAX_KNOWN_SUITEMASKS 18
static VALUE_DESC SuiteMasks[MAX_KNOWN_SUITEMASKS] = {
	{ L"ServerNT", VER_SERVER_NT },
	{ L"WorkstationNT", VER_WORKSTATION_NT },
	{ L"SmallBusiness", VER_SUITE_SMALLBUSINESS },
	{ L"Enterprise", VER_SUITE_ENTERPRISE },
	{ L"BackOffice", VER_SUITE_BACKOFFICE },
	{ L"Communications", VER_SUITE_COMMUNICATIONS },
	{ L"Terminal", VER_SUITE_TERMINAL },
	{ L"SmallBussinessRestricted", VER_SUITE_SMALLBUSINESS_RESTRICTED },
	{ L"EmbeddedNT", VER_SUITE_EMBEDDEDNT },
	{ L"DataCenter", VER_SUITE_DATACENTER },
	{ L"SingleUserTS", VER_SUITE_SINGLEUSERTS },
	{ L"Personal", VER_SUITE_PERSONAL },
	{ L"Blade", VER_SUITE_BLADE },
	{ L"EmbeddedRestricted", VER_SUITE_EMBEDDED_RESTRICTED },
	{ L"SecurityAppliance", VER_SUITE_SECURITY_APPLIANCE },
	{ L"StorageServer", VER_SUITE_STORAGE_SERVER },
	{ L"ComputeServer", VER_SUITE_COMPUTE_SERVER },
	{ L"HomeServer", VER_SUITE_WH_SERVER }
};

LPCWSTR T_SharedDataFlags[9] = {
	L"DbgErrorPortPresent",
	L"DbgElevationEnabled",
	L"DbgVirtEnabled",
	L"DbgInstallerDetectEnabled",
	L"DbgLkgEnabled",
	L"DbgDynProcessorEnabled",
	L"DbgConsoleBrokerEnabled",
	L"DbgSecureBootEnabled",
	L"DbgMultiSessionSku"
};

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
	BOOL					bCond = FALSE;
	INT						i;
	DWORD					mask;
	HWND					UsdTreeList;
	ATOM					UsdTreeListAtom;

	NTSTATUS				status;
	SIZE_T					memIO = 0x1000;
	PKUSER_SHARED_DATA		pData = NULL;

	HTREEITEM				h_tviRootItem, h_tviSubItem;
	LPWSTR					lpType;
	TL_SUBITEMS_FIXED		subitems;
	WCHAR					szValue[MAX_PATH + 1];

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
			TVIS_EXPANDED, L"KUSER_SHARED_DATA", NULL);
		if (h_tviRootItem == NULL) {
			break;
		}

		//NtSystemRoot
		RtlSecureZeroMemory(&subitems, sizeof(subitems));
		subitems.Text[0] = pData->NtSystemRoot;
		subitems.Count = 1;
		TreeListAddItem(UsdTreeList, h_tviRootItem, TVIF_TEXT | TVIF_STATE, 0, 0, L"NtSystemRoot", &subitems);

		//NtProductType
		switch (pData->NtProductType) {
		case NtProductWinNt:
			lpType = L"NtProductWinNt";
			break;
		case NtProductLanManNt:
			lpType = L"NtProductLanManNt";
			break;
		case NtProductServer:
			lpType = L"NtProductServer";
			break;	
		default:
			lpType = T_UnknownType;
			break;
		}
		ObDumpUlong(UsdTreeList, h_tviRootItem, L"NtProductType", lpType, pData->NtProductType, FALSE, FALSE, 0, 0);
		ObDumpByte(UsdTreeList, h_tviRootItem, L"ProductTypeIsValid", NULL, pData->ProductTypeIsValid, 0, 0, TRUE);
		
		//Version
		ObDumpUlong(UsdTreeList, h_tviRootItem, L"NtMajorVersion", NULL, pData->NtMajorVersion, FALSE, FALSE, 0, 0);
		ObDumpUlong(UsdTreeList, h_tviRootItem, L"NtMinorVersion", NULL, pData->NtMinorVersion, FALSE, FALSE, 0, 0);

		//ProcessorFeatures
		h_tviSubItem = TreeListAddItem(UsdTreeList, h_tviRootItem, TVIF_TEXT | TVIF_STATE, 0, 0, L"ProcessorFeatures", NULL);
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
			lpType = L"StandardDesign";
			break;
		case NEC98x86:
			lpType = L"NEC98x86";
			break;
		default: 
			lpType = T_UnknownType;
			break;
		}
		ObDumpUlong(UsdTreeList, h_tviRootItem, L"AlternativeArchitecture", lpType, pData->AlternativeArchitecture, FALSE, FALSE, 0, 0);

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
		ObDumpByte(UsdTreeList, h_tviRootItem, L"KdDebuggerEnabled", NULL, pData->KdDebuggerEnabled, 0, 0, TRUE);

		//MitigationPolicies
		ObDumpByte(UsdTreeList, h_tviRootItem, L"MitigationPolicies", NULL, pData->MitigationPolicies, 0, 0, FALSE);

		//SafeBootMode
		ObDumpByte(UsdTreeList, h_tviRootItem, L"SafeBootMode", NULL, pData->SafeBootMode, 0, 0, TRUE);

		//SharedDataFlags
		RtlSecureZeroMemory(&subitems, sizeof(subitems));
		RtlSecureZeroMemory(&szValue, sizeof(szValue));
		szValue[0] = L'0';
		szValue[1] = L'x';
		ultohex_w(pData->SharedDataFlags, &szValue[2]);
		subitems.Text[0] = szValue;
		subitems.Count = 1;
		h_tviSubItem = TreeListAddItem(UsdTreeList, h_tviRootItem, TVIF_TEXT | TVIF_STATE, 0, 0, L"SharedDataFlags", &subitems);
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
		UsdDialog = NULL;
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
	if (UsdDialog) {
		return;
	}

	UsdDialog = CreateDialogParam(g_hInstance, MAKEINTRESOURCE(IDD_DIALOG_USD),
		hwndParent, &UsdDialogProc, 0);

	if (UsdDialog == NULL) {
		return;
	}

	UsdDumpSharedRegion(UsdDialog);
}
