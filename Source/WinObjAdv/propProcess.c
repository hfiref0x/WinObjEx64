/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       PROPPROCESS.C
*
*  VERSION:     1.10
*
*  DATE:        25 Feb 2015
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "propDlg.h"
#include "propProcess.h"

//number of columns, revise this unit code after any change to this number
#define PROCESSLIST_COLUMN_COUNT 4

//page imagelist
HIMAGELIST ProcessImageList = NULL;
//page listview
HWND ProcessList = NULL;
//column to sort
static LONG	ProcessListSortColumn = 0;
//sort direction
BOOL bProcessListSortInverse = FALSE;

/*
* ProcessListCompareFunc
*
* Purpose:
*
* Process page listview comparer function.
*
*/
INT CALLBACK ProcessListCompareFunc(
	_In_ LPARAM lParam1,
	_In_ LPARAM lParam2,
	_In_ LPARAM lParamSort
	)
{
	LPWSTR lpItem1, lpItem2;
	INT nResult, k;
	SIZE_T sz1, sz2;
	ULONG_PTR Value1, Value2;

	sz1 = 0;
	lpItem1 = supGetItemText(ProcessList, (INT)lParam1, (INT)lParamSort, &sz1);
	if (lpItem1 == NULL) //can't be 0 for this dialog
		return 0;

	sz2 = 0;
	lpItem2 = supGetItemText(ProcessList, (INT)lParam2, (INT)lParamSort, &sz2);
	if (lpItem2 == NULL) //can't be 0 for this dialog
		return 0;

	switch (lParamSort) {
	case 0: //name column

		if (bProcessListSortInverse)
			nResult = _strcmpi(lpItem2, lpItem1);
		else
			nResult = _strcmpi(lpItem1, lpItem2);

		break;
	case 1: // id column
		Value1 = strtou64(lpItem1);
		Value2 = strtou64(lpItem2);
		if (bProcessListSortInverse)
			nResult = Value2 > Value1;
		else
			nResult = Value1 > Value2;
		break;

		//anything else is hex
	default:

		k = 0;
		if ((sz1 > 1) && (sz2 > 1)) {
			if (lpItem1[1] == L'x')
				k = 2;
		}

		Value1 = hextou64(&lpItem1[k]);
		Value2 = hextou64(&lpItem2[k]);
		if (bProcessListSortInverse)
			nResult = Value2 > Value1;
		else
			nResult = Value1 > Value2;
		break;
	}

	HeapFree(GetProcessHeap(), 0, lpItem1);
	HeapFree(GetProcessHeap(), 0, lpItem2);
	return nResult;
}

VOID ProcessShowProperties(
	HWND hwndDlg,
	INT iItem
	)
{
	LPWSTR				Buffer;
	DWORD				dwProcessId;
	ULONG				bytesNeeded;
	HANDLE				hProcess;
	NTSTATUS			status;
	PUNICODE_STRING		dynUstr;
	OBJECT_ATTRIBUTES	obja;
	CLIENT_ID			cid;

	__try {
		//query process id
		Buffer = supGetItemText(ProcessList, iItem, 1, NULL);
		if (Buffer) {
			dwProcessId = strtoul(Buffer);
			HeapFree(GetProcessHeap(), 0, Buffer);

			//query process win32 image path
			//1. open target process
			cid.UniqueProcess = (HANDLE)dwProcessId;
			cid.UniqueThread = NULL;
			InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
			status = NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &obja, &cid);
			if (NT_SUCCESS(status)) {
				bytesNeeded = 0;
				//2. query required buffer size
				NtQueryInformationProcess(hProcess, ProcessImageFileNameWin32, NULL, 0, &bytesNeeded);
				if (bytesNeeded) {
					Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytesNeeded);
					if (Buffer) {
						//3. query win32 filename
						status = NtQueryInformationProcess(hProcess, ProcessImageFileNameWin32, Buffer,
							bytesNeeded, &bytesNeeded);
						if (NT_SUCCESS(status)) {
							dynUstr = (PUNICODE_STRING)Buffer;
							if (dynUstr->Buffer && dynUstr->Length) {
								//4. shellexecute properties dialog
								supShowProperties(hwndDlg, dynUstr->Buffer);
							}
						}
						HeapFree(GetProcessHeap(), 0, Buffer);
					}
				}
				NtClose(hProcess);
			}
		}
	}
	__except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
		return;
	}
}


/*
* ProcessListHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for Process page listview.
*
*/
VOID ProcessListHandleNotify(
	HWND hwndDlg,
	LPARAM lParam
	)
{
	LVCOLUMNW		col;
	INT				c;
	LPNMHDR			nhdr = (LPNMHDR)lParam;

	if (nhdr == NULL)
		return;

	if (nhdr->idFrom != ID_PROCESSLIST)
		return;

	switch (nhdr->code) {

	case LVN_COLUMNCLICK:
		bProcessListSortInverse = !bProcessListSortInverse;
		ProcessListSortColumn = ((NMLISTVIEW *)nhdr)->iSubItem;
		ListView_SortItemsEx(ProcessList, &ProcessListCompareFunc, ProcessListSortColumn);

		RtlSecureZeroMemory(&col, sizeof(col));
		col.mask = LVCF_IMAGE;
		col.iImage = -1;

		for (c = 0; c < PROCESSLIST_COLUMN_COUNT; c++)
			ListView_SetColumn(ProcessList, c, &col);

		if (bProcessListSortInverse)
			col.iImage = 1;
		else
			col.iImage = 2;

		ListView_SetColumn(ProcessList, ((NMLISTVIEW *)nhdr)->iSubItem, &col);
		break;

	case NM_DBLCLK:
		ProcessShowProperties(hwndDlg, ((LPNMITEMACTIVATE)lParam)->iItem);
		break;

	default:
		break;
	}
}


/*
* ProcessQueryInfo
*
* Purpose:
*
* Extracts icon resource from given process for use in listview and determines process WOW64 status
*
*/
BOOL ProcessQueryInfo(
	_In_ DWORD ProcessId,
	_Out_ HICON *pProcessIcon,
	_Out_ BOOL *pbIs32
	)
{
	BOOL				bResult = FALSE, bIconFound, bWow64State;
	ULONG				bytesNeeded;
	HANDLE				hProcess;
	NTSTATUS			status;
	PVOID				Buffer;
	PUNICODE_STRING		dynUstr;
	OBJECT_ATTRIBUTES	obja;
	CLIENT_ID			cid;

	PROCESS_EXTENDED_BASIC_INFORMATION pebi;

	if ((pProcessIcon == NULL) || (pbIs32 == NULL)) {
		return bResult;
	}

	*pProcessIcon = NULL;
	*pbIs32 = FALSE;

	bWow64State = FALSE;
	bIconFound = FALSE;
	__try {
		cid.UniqueProcess = (HANDLE)ProcessId;
		cid.UniqueThread = NULL;

		InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
		status = NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &obja, &cid);
		if (!NT_SUCCESS(status)) {
			return bResult;
		}
		//query process icon, first query win32 imagefilename then parse image resources
		bytesNeeded = 0;
		NtQueryInformationProcess(hProcess, ProcessImageFileNameWin32, NULL, 0, &bytesNeeded);
		if (bytesNeeded) {
			Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytesNeeded);
			if (Buffer) {
				status = NtQueryInformationProcess(hProcess, ProcessImageFileNameWin32, Buffer, 
					bytesNeeded, &bytesNeeded);
				if (NT_SUCCESS(status)) {
					dynUstr = (PUNICODE_STRING)Buffer;
					if (dynUstr->Buffer && dynUstr->Length) {
						*pProcessIcon = supGetMainIcon(dynUstr->Buffer, 16, 16);
						bIconFound = TRUE;
					}
				}
				HeapFree(GetProcessHeap(), 0, Buffer);
			}
		}

		//query if this is wow64 process
		RtlSecureZeroMemory(&pebi, sizeof(pebi));
		pebi.Size = sizeof(PROCESS_EXTENDED_BASIC_INFORMATION);
		status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pebi, sizeof(pebi), NULL);
		if (NT_SUCCESS(status)) {
			*pbIs32 = (pebi.IsWow64Process);
			bWow64State = TRUE;
		}

		NtClose(hProcess);
	}
	__except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
		return FALSE;
	}
	bResult = (bIconFound && bWow64State);
	return bResult;
}

/*
* ProcessListAddItem
*
* Purpose:
*
* Adds an item to the listview.
*
*/
VOID ProcessListAddItem(
	_In_ PVOID	ProcessesList,
	_In_ PSYSTEM_HANDLE_TABLE_ENTRY_INFO phti
	)
{
	BOOL			bIsWow64;
	INT				nIndex, iImage;
	LVITEMW			lvitem;
	HICON			hIcon;
	WCHAR			szBuffer[MAX_PATH * 2];

	if ((phti == NULL) || (ProcessesList == NULL)) {
		return;
	}

	//default image index
	iImage = 0;

	//set default process name as Unknown
	RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
	_strcpy(szBuffer, T_Unknown);

	if (supQueryProcessName(phti->UniqueProcessId,
		ProcessesList, szBuffer, MAX_PATH)) {

		//id exists, extract icon
		//skip idle, system
		if (phti->UniqueProcessId <= 4) {
			iImage = 0;
		}
		else {
			hIcon = NULL;
			bIsWow64 = FALSE;
			if (ProcessQueryInfo(phti->UniqueProcessId, &hIcon, &bIsWow64)) {
				if (hIcon) {
					iImage = ImageList_ReplaceIcon(ProcessImageList, -1, hIcon);
					DestroyIcon(hIcon);
				}
				if (bIsWow64) {
					_strcat(szBuffer, L"*32");
				}
			} //ProcessQueryInfo
		} //else
	}

	//Name
	RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
	lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
	lvitem.iImage = iImage;
	lvitem.iSubItem = 0;
	lvitem.pszText = szBuffer;
	lvitem.iItem = MAXINT;
	nIndex = ListView_InsertItem(ProcessList, &lvitem);

	//ID
	RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
	ultostr(phti->UniqueProcessId, szBuffer);
	lvitem.mask = LVIF_TEXT;
	lvitem.iSubItem = 1;
	lvitem.pszText = szBuffer;
	lvitem.iItem = nIndex;
	ListView_SetItem(ProcessList, &lvitem);

	//Value
	RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
	_strcpy(szBuffer, L"0x");
	ultohex(phti->HandleValue, _strend(szBuffer));
	lvitem.mask = LVIF_TEXT;
	lvitem.iSubItem = 2;
	lvitem.pszText = szBuffer;
	lvitem.iItem = nIndex;
	ListView_SetItem(ProcessList, &lvitem);

	//GrantedAccess
	RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
	_strcpy(szBuffer, L"0x");
	ultohex(phti->GrantedAccess, _strend(szBuffer));
	lvitem.mask = LVIF_TEXT;
	lvitem.iSubItem = 3;
	lvitem.pszText = szBuffer;
	lvitem.iItem = nIndex;
	ListView_SetItem(ProcessList, &lvitem);
}

/*
* ProcessListSetInfo
*
* Purpose:
*
* Query information and fill listview.
* Called each time when page became visible.
*
*/
VOID ProcessListSetInfo(
	PROP_OBJECT_INFO *Context,
	_In_ HWND hwndDlg
	)
{
	BOOL							cond = FALSE;
	UCHAR							ObjectTypeIndex;
	ULONG							i;
	DWORD							CurrentProcessId = GetCurrentProcessId();
	ULONG_PTR						ObjectAddress;
	HICON							hIcon;
	ACCESS_MASK						DesiredAccess;
	PVOID							ProcessesList;
	HANDLE							hObject, tmpb;
	PSYSTEM_HANDLE_INFORMATION		pHandles;

	if (Context == NULL) {
		return;
	}

	hObject = NULL;
	pHandles = NULL;
	ProcessesList = NULL;
	ObjectAddress = 0;
	ObjectTypeIndex = 0;

	//empty process list images
	ImageList_RemoveAll(ProcessImageList);

	//empty process list
	ListView_DeleteAllItems(GetDlgItem(hwndDlg, ID_PROCESSLIST));

	//set default app icon
	hIcon = LoadIcon(NULL, IDI_APPLICATION);
	if (hIcon) {
		ImageList_ReplaceIcon(ProcessImageList, -1, hIcon);
		DestroyIcon(hIcon);
	}
	//sort images
	tmpb = LoadImage(g_hInstance, MAKEINTRESOURCE(IDI_ICON_SORTUP), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
	if (tmpb) {
		ImageList_ReplaceIcon(ProcessImageList, -1, tmpb);
		DestroyIcon(tmpb);
	}
	tmpb = LoadImage(g_hInstance, MAKEINTRESOURCE(IDI_ICON_SORTDOWN), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
	if (tmpb) {
		ImageList_ReplaceIcon(ProcessImageList, -1, tmpb);
		DestroyIcon(tmpb);
	}

	//check if additional info available
	if (Context->ObjectInfo.ObjectAddress != 0) {
		ObjectAddress = Context->ObjectInfo.ObjectAddress;
		ObjectTypeIndex = Context->ObjectInfo.ObjectHeader.TypeIndex;
	}

	do {
		//object info not present
		if (ObjectAddress == 0) {
			switch (Context->TypeIndex) {
			case TYPE_DIRECTORY:
				DesiredAccess = DIRECTORY_QUERY;
				break;
			case TYPE_EVENT:
				DesiredAccess = EVENT_QUERY_STATE;
				break;
			case TYPE_MUTANT:
				DesiredAccess = MUTANT_QUERY_STATE;
				break;
			case TYPE_SEMAPHORE:
				DesiredAccess = SEMAPHORE_QUERY_STATE;
				break;
			case TYPE_SECTION:
				DesiredAccess = SECTION_QUERY;
				break;
			case TYPE_SYMLINK:
				DesiredAccess = SYMBOLIC_LINK_QUERY;
				break;
			case TYPE_TIMER:
				DesiredAccess = TIMER_QUERY_STATE;
				break;
			case TYPE_JOB:
				DesiredAccess = JOB_OBJECT_QUERY;
				break;
			case TYPE_WINSTATION:
				DesiredAccess = WINSTA_READATTRIBUTES;
				break;
			case TYPE_IOCOMPLETION:
				DesiredAccess = IO_COMPLETION_QUERY_STATE;
				break;
			default:
				DesiredAccess = MAXIMUM_ALLOWED;
				break;
			}
			//open temporary object handle to query object address
			if (!propOpenCurrentObject(Context, &hObject, DesiredAccess)) {
				break;
			}
		}

		pHandles = (PSYSTEM_HANDLE_INFORMATION)supGetSystemInfo(SystemHandleInformation);
		if (pHandles == NULL) {
			break;
		}

		ProcessesList = supGetSystemInfo(SystemProcessInformation);
		if (ProcessesList == NULL) {
			break;
		}

		//no additional info available which mean we must query object address by yourself
		if (ObjectAddress == 0) {
			//find our handle object by handle value
			for (i = 0; i < pHandles->NumberOfHandles; i++)
				if (pHandles->Handles[i].UniqueProcessId == CurrentProcessId)
					if (pHandles->Handles[i].HandleValue == (USHORT)(ULONG_PTR)hObject) {
						ObjectAddress = (ULONG_PTR)pHandles->Handles[i].Object;
						ObjectTypeIndex = pHandles->Handles[i].ObjectTypeIndex;
						break;
					}
		}

		//object no longer needed
		if (hObject) {
			NtClose(hObject);
			hObject = NULL;
		}

		//nothing to compare
		if (ObjectAddress == 0) {
			break;
		}

		//retake snapshot
		HeapFree(GetProcessHeap(), 0, pHandles);
		pHandles = (PSYSTEM_HANDLE_INFORMATION)supGetSystemInfo(SystemHandleInformation);
		if (pHandles == NULL) {
			break;
		}

		//find any handles with the same object address and object type
		for (i = 0; i < pHandles->NumberOfHandles; i++)
			if (pHandles->Handles[i].ObjectTypeIndex == ObjectTypeIndex) {
				if ((ULONG_PTR)pHandles->Handles[i].Object == ObjectAddress) {
					//decode and add information to the list
					ProcessListAddItem(ProcessesList, &pHandles->Handles[i]);
				}
			}

	} while (cond);

	//cleanup
	if (pHandles) {
		HeapFree(GetProcessHeap(), 0, pHandles);
	}
	if (ProcessList) {
		HeapFree(GetProcessHeap(), 0, ProcessesList);
	}
	if (Context->TypeIndex == TYPE_WINSTATION && hObject) {
		CloseWindowStation(hObject);
		hObject = NULL;
	}
	if (hObject) {
		NtClose(hObject);
	}
	//show/hide notification text
	ShowWindow(GetDlgItem(hwndDlg, ID_PROCESSLISTNOALL), (ObjectAddress == 0) ? SW_SHOW : SW_HIDE);
}

/*
* ProcessListCreate
*
* Purpose:
*
* Initialize listview for process list.
* Called once.
*
*/
VOID ProcessListCreate(
	_In_ HWND hwndDlg
	)
{
	LVCOLUMNW	col;

	ProcessList = GetDlgItem(hwndDlg, ID_PROCESSLIST);
	if (ProcessList == NULL)
		return;

	ProcessImageList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 32, 8);
	if (ProcessImageList) {
		ListView_SetImageList(ProcessList, ProcessImageList, LVSIL_SMALL);
	}

	ListView_SetExtendedListViewStyle(ProcessList, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

	RtlSecureZeroMemory(&col, sizeof(col));
	col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER | LVCF_IMAGE;
	col.iSubItem = 1;
	col.pszText = L"Process";
	col.fmt = LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT;
	col.iOrder = 0;
	col.iImage = 2;
	col.cx = 160;
	ListView_InsertColumn(ProcessList, 1, &col);

	col.iSubItem = 2;
	col.pszText = L"ID";
	col.iOrder = 1;
	col.iImage = -1;
	col.cx = 60;
	ListView_InsertColumn(ProcessList, 2, &col);

	col.iSubItem = 3;
	col.pszText = L"Handle";
	col.iOrder = 2;
	col.iImage = -1;
	col.cx = 80;
	ListView_InsertColumn(ProcessList, 3, &col);

	col.iSubItem = 4;
	col.pszText = L"Access";
	col.iOrder = 3;
	col.iImage = -1;
	col.cx = 80;
	ListView_InsertColumn(ProcessList, 4, &col);
}

/*
* ProcessHandlePopupMenu
*
* Purpose:
*
* Process list popup construction
*
*/
VOID ProcessHandlePopupMenu(
	_In_ HWND hwndDlg
	)
{
	POINT pt1;
	HMENU hMenu;

	if (GetCursorPos(&pt1) != TRUE)
		return;

	hMenu = CreatePopupMenu();
	if (hMenu == NULL)
		return;

	InsertMenu(hMenu, 0, MF_BYCOMMAND, ID_OBJECT_COPY, T_COPYTEXTROW);

	TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, pt1.x, pt1.y, 0, hwndDlg, NULL);
	DestroyMenu(hMenu);
}

/*
* ProcessCopyText
*
* Purpose:
*
* Copy selected list view row to the clipboard.
*
*/
VOID ProcessCopyText(
	_In_ HWND hwndDlg
	)
{
	INT		nSelection, i;
	SIZE_T	cbText, sz;
	LPWSTR	lpText, lpItemText[4];
	HWND	hwndList;


	hwndList = GetDlgItem(hwndDlg, ID_PROCESSLIST);
	if (hwndList == NULL) {
		return;
	}

	if (ListView_GetSelectedCount(hwndList) == 0) {
		return;
	}

	nSelection = ListView_GetSelectionMark(hwndList);
	if (nSelection == -1) {
		return;
	}

	__try {
		cbText = 0;
		for (i = 0; i < PROCESSLIST_COLUMN_COUNT; i++) {
			sz = 0;
			lpItemText[i] = supGetItemText(hwndList, nSelection, i, &sz);
			cbText += sz;
		}

		cbText += (PROCESSLIST_COLUMN_COUNT * sizeof(WCHAR)) + sizeof(UNICODE_NULL);
		lpText = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbText);
		if (lpText) {

			for (i = 0; i < PROCESSLIST_COLUMN_COUNT; i++) {
				if (lpItemText[i]) {
					_strcat(lpText, lpItemText[i]);
					if (i != 3) {
						_strcat(lpText, L" ");
					}
				}
			}
			supClipboardCopy(lpText, cbText);
			HeapFree(GetProcessHeap(), 0, lpText);
		}
		for (i = 0; i < PROCESSLIST_COLUMN_COUNT; i++) {
			if (lpItemText[i] != NULL) {
				HeapFree(GetProcessHeap(), 0, lpItemText[i]);
			}
		}
	}
	__except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
		return;
	}
}

/*
* ProcessListDialogProc
*
* Purpose:
*
* Process list page for various object types.
*
* WM_INITDIALOG - Initialize listview, set window prop with context,
* collect processes info and fill list.
*
* WM_NOTIFY - Handle list view notifications.
*
* WM_DESTROY - Free image list and remove window prop.
*
* WM_CONTEXTMENU - Handle popup menu.
*
*/
INT_PTR CALLBACK ProcessListDialogProc(
	_In_  HWND hwndDlg,
	_In_  UINT uMsg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
	)
{
	PROPSHEETPAGE *pSheet = NULL;
	PROP_OBJECT_INFO *Context = NULL;

	switch (uMsg) {

	case WM_CONTEXTMENU:
		ProcessHandlePopupMenu(hwndDlg);
		break;

	case WM_COMMAND:

		if (LOWORD(wParam) == ID_OBJECT_COPY) {
			ProcessCopyText(hwndDlg);
		}
		break;

	case WM_NOTIFY:
		ProcessListHandleNotify(hwndDlg, lParam);
		return 1;
		break;

	case WM_DESTROY:
		if (ProcessImageList) {
			ImageList_Destroy(ProcessImageList);
		}
		RemoveProp(hwndDlg, T_PROPCONTEXT);
		break;

	case WM_INITDIALOG:

		pSheet = (PROPSHEETPAGE *)lParam;
		if (pSheet) {
			Context = (PROP_OBJECT_INFO *)pSheet->lParam;
			SetProp(hwndDlg, T_PROPCONTEXT, (HANDLE)Context);

			ProcessListCreate(hwndDlg);
			if (ProcessList) {
				ProcessListSetInfo(Context, hwndDlg);
				ListView_SortItemsEx(ProcessList, &ProcessListCompareFunc, ProcessListSortColumn);
			}

		}
		return 1;
		break;

	}
	return 0;
}