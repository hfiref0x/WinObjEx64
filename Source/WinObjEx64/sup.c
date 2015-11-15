/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       SUP.C
*
*  VERSION:     1.31
*
*  DATE:        12 Nov 2015
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "treelist.h"
#include "extrasSSDT.h"
#include <cfgmgr32.h>
#include <setupapi.h>

#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Setupapi.lib")

//used while objects enumeration in listview
ENUM_PARAMS	g_enumParams;

//types collection
POBJECT_TYPES_INFORMATION g_pObjectTypesInfo = NULL;

//Known object type names
LPCWSTR T_ObjectNames[TYPE_MAX] = {
	L"Device",						//0
	L"Driver",						//1
	L"Section",						//2
	L"ALPC Port",					//3
	L"SymbolicLink",				//4
	L"Key",							//5
	L"Event",						//6
	L"Job",							//7
	L"Mutant",						//8
	L"KeyedEvent",					//9
	L"Type",						//10
	L"Directory",					//11
	L"WindowStation",				//12
	L"Callback",					//13
	L"Semaphore",					//14
	L"WaitablePort",				//15
	L"Timer",						//16
	L"Session",						//17
	L"Controller",					//18
	L"Profile",						//19
	L"EventPair",					//20
	L"Desktop",						//21
	L"File",						//22
	L"WMIGuid",						//23
	L"DebugObject",					//24
	L"IoCompletion",				//25
	L"Process",						//26
	L"Adapter",						//27
	L"Token",						//28
	L"EtwRegistration",				//29
	L"Thread",						//30
	L"TmTx",						//31
	L"TmTm",						//32
	L"TmRm",						//33
	L"TmEn",						//34
	L"PcwObject",					//35
	L"FilterConnectionPort",		//36
	L"FilterCommunicationPort",		//37
	L"PowerRequest",				//38
	L"EtwConsumer",					//39
	L"TpWorkerFactory",				//40
	L"Composition",					//41
	L"IRTimer",						//42
	L"DxgkSharedResource",			//43
	L"DxgkSharedSwapChainObject",	//44
	L"DxgkSharedSyncObject",		//45
	L""								//46
};

/*
* supInitTreeListForDump
*
* Purpose:
*
* Intialize TreeList control for object dump sheet.
*
*/
BOOL supInitTreeListForDump(
	_In_  HWND  hwndParent,
	_Inout_ ATOM *pTreeListAtom,
	_Inout_ HWND *pTreeListHwnd
	)
{
	ATOM		TreeListAtom;
	HWND		TreeList;
	HDITEM		hdritem;
	RECT		rc;

	if ((pTreeListAtom == NULL) || (pTreeListHwnd == NULL)) {
		return FALSE;
	}

	GetClientRect(hwndParent, &rc);
	TreeListAtom = InitializeTreeListControl();
	TreeList = CreateWindowEx(WS_EX_CLIENTEDGE, WC_TREELIST, NULL,
		WS_VISIBLE | WS_CHILD | WS_TABSTOP | TLSTYLE_COLAUTOEXPAND, 12, 20, 
		rc.right - 24, rc.bottom - 30, hwndParent, NULL, NULL, NULL);

	if (TreeList == NULL) {
		UnregisterClass(MAKEINTATOM(TreeListAtom), g_hInstance);
		*pTreeListHwnd = NULL;
		*pTreeListAtom = 0;
		return FALSE;
	}

	*pTreeListHwnd = TreeList;
	*pTreeListAtom = TreeListAtom;

	RtlSecureZeroMemory(&hdritem, sizeof(hdritem));
	hdritem.mask = HDI_FORMAT | HDI_TEXT | HDI_WIDTH;
	hdritem.fmt = HDF_LEFT | HDF_BITMAP_ON_RIGHT | HDF_STRING;
	hdritem.cxy = 220;
	hdritem.pszText = L"Field";
	TreeList_InsertHeaderItem(TreeList, 0, &hdritem);
	hdritem.cxy = 130;
	hdritem.pszText = L"Value";
	TreeList_InsertHeaderItem(TreeList, 1, &hdritem);
	hdritem.cxy = 200;
	hdritem.pszText = L"Additional Information";
	TreeList_InsertHeaderItem(TreeList, 2, &hdritem);

	return TRUE;
}

/*
* supClipboardCopy
*
* Purpose:
*
* Copy text to the clipboard.
*
*/
VOID supClipboardCopy(
	_In_ LPWSTR lpText,
	_In_ SIZE_T cbText
	)
{
	LPWSTR  lptstrCopy;
	HGLOBAL hglbCopy;
	SIZE_T	dwSize;

	if (OpenClipboard(NULL)) {
		EmptyClipboard();
		dwSize = cbText + sizeof(UNICODE_NULL);
		hglbCopy = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, dwSize);
		if (hglbCopy != NULL) {
			lptstrCopy = GlobalLock(hglbCopy);
			if (lptstrCopy) {
				supCopyMemory(lptstrCopy, dwSize, lpText, cbText);
			}
			GlobalUnlock(hglbCopy);
			SetClipboardData(CF_UNICODETEXT, hglbCopy);
		}
		CloseClipboard();
	}
}


/*
* supQueryObjectFromHandle
*
* Purpose:
*
* Return object kernel address from handle in current process handle table.
*
*/
BOOL supQueryObjectFromHandle(
	_In_ HANDLE hOject,
	_Inout_ ULONG_PTR *Address,
	_Inout_opt_ UCHAR *TypeIndex
	)
{
	BOOL bFound = FALSE;
	ULONG i;
	DWORD CurrentProcessId = GetCurrentProcessId();
	PSYSTEM_HANDLE_INFORMATION pHandles;

	if (Address == NULL) {
		return bFound;
	}
	pHandles = (PSYSTEM_HANDLE_INFORMATION)supGetSystemInfo(SystemHandleInformation);
	if (pHandles) {
		for (i = 0; i < pHandles->NumberOfHandles; i++) {
			if (pHandles->Handles[i].UniqueProcessId == CurrentProcessId) {
				if (pHandles->Handles[i].HandleValue == (USHORT)(ULONG_PTR)hOject) {
					if ((ULONG_PTR)pHandles->Handles[i].Object < g_kdctx.SystemRangeStart) {
						*Address = 0;
						if (TypeIndex) {
							*TypeIndex = 0;
						}
					}
					else {
						*Address = (ULONG_PTR)pHandles->Handles[i].Object;
						if (TypeIndex) {
							*TypeIndex = pHandles->Handles[i].ObjectTypeIndex;
						}
						bFound = TRUE;
					}
					break;

				}
			}
		}
		HeapFree(GetProcessHeap(), 0, pHandles);
	}
	return bFound;
}

/*
* supSyscallTableEntryToAddress
*
* Purpose:
*
* Translate KiServiceTable entry to the real function address.
*
*/
ULONG_PTR supSyscallTableEntryToAddress(
	PULONG KiServiceTable,
	ULONG ServiceId,
	ULONG_PTR KiServiceTablePtr
	)
{
	LONG32 Offset;

	Offset = ((LONG32)KiServiceTable[ServiceId] >> 4);
	return KiServiceTablePtr + Offset;
}

/*
* supDumpSyscallTableConverted
*
* Purpose:
*
* Read KiServiceTable and convert it.
*
*/
BOOL supDumpSyscallTableConverted(
	_In_ PKLDBGCONTEXT Context,
	_Inout_ PUTable *Table
	)
{
	ULONG memIO = 0;
	BOOL bResult = FALSE, cond = FALSE;

	PULONG KiServiceTableDumped = NULL;
	ULONG ServiceId;
	PUTable ConvertedTable;

	if ((Context == NULL) || (Table == NULL))
		return bResult;

	do {

		if (Context->KiServiceTableAddress == 0)
			break;

		memIO = Context->KiServiceLimit * sizeof(ULONG_PTR);
		KiServiceTableDumped = (PULONG)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, memIO);
		if (KiServiceTableDumped == NULL)
			break;

		if (!kdReadSystemMemory(Context->KiServiceTableAddress, (PVOID)KiServiceTableDumped, memIO))
			break;

		ConvertedTable = (PULONG_PTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, memIO);
		if (ConvertedTable == NULL)
			break;

		*Table = ConvertedTable;

		for (ServiceId = 0; ServiceId < Context->KiServiceLimit; ServiceId++) {
			ConvertedTable[ServiceId] = supSyscallTableEntryToAddress(KiServiceTableDumped, ServiceId,
				Context->KiServiceTableAddress);
		}

		bResult = TRUE;

	} while (cond);

	if (KiServiceTableDumped != NULL) {
		HeapFree(GetProcessHeap(), 0, KiServiceTableDumped);
	}
	return bResult;
}

/*
* supShowHelp
*
* Purpose:
*
* Display help file if available.
*
*/
VOID supShowHelp(
	VOID
	)
{
	DWORD dwSize;
	HKEY hKey;
	LRESULT lRet;
	HANDLE hHtmlOcx;
	WCHAR szOcxPath[MAX_PATH + 1];
	WCHAR szHelpFile[MAX_PATH * 2];

	RtlSecureZeroMemory(&szOcxPath, sizeof(szOcxPath));
	RtlSecureZeroMemory(szHelpFile, sizeof(szHelpFile));
	lRet = RegOpenKeyEx(HKEY_CLASSES_ROOT, HHCTRLOCXKEY, 0, KEY_QUERY_VALUE, &hKey);
	if (lRet == ERROR_SUCCESS) {
		dwSize = MAX_PATH * sizeof(WCHAR);
		lRet = RegQueryValueEx(hKey, L"", NULL, NULL, (LPBYTE)szHelpFile, &dwSize);
		RegCloseKey(hKey);

		if (lRet == ERROR_SUCCESS) {
			if (ExpandEnvironmentStrings(szHelpFile, szOcxPath, MAX_PATH) == 0) {
				lRet = ERROR_SECRET_TOO_LONG;
			}
		}
	}
	if (lRet != ERROR_SUCCESS) {
		_strcpy(szOcxPath, HHCTRLOCX);
	}

	RtlSecureZeroMemory(szHelpFile, sizeof(szHelpFile));
	if (!GetCurrentDirectory(MAX_PATH, szHelpFile)) {
		return;
	}
	_strcat(szHelpFile, L"\\winobjex64.chm");

	hHtmlOcx = GetModuleHandle(HHCTRLOCX);
	if (hHtmlOcx == NULL) {
		hHtmlOcx = LoadLibrary(szOcxPath);
		if (hHtmlOcx == NULL) {
			return;
		}
	}
	if (pHtmlHelpW == NULL) {
		pHtmlHelpW = (pfnHtmlHelpW)GetProcAddress(hHtmlOcx, MAKEINTRESOURCEA(0xF));
		if (pHtmlHelpW == NULL) {
			return;
		}
	}
	pHtmlHelpW(GetDesktopWindow(), szHelpFile, 0, 0);
}

/*
* supEnumIconCallback
*
* Purpose:
*
* Resource enumerator callback.
*
*/
BOOL supEnumIconCallback(
	_In_opt_ HMODULE hModule,
	_In_ LPCWSTR lpType,
	_In_ LPWSTR lpName,
	_In_ LONG_PTR lParam
	)
{
	PENUMICONINFO pin;

	UNREFERENCED_PARAMETER(lpType);

	pin = (PENUMICONINFO)lParam;
	if (pin == NULL) {
		return FALSE;
	}

	pin->hIcon = (HICON)LoadImage(hModule, lpName, IMAGE_ICON, pin->cx, pin->cy, 0);
	return FALSE;
}

/*
* supGetMainIcon
*
* Purpose:
*
* Extract main icon if it exists in executable image.
*
*/
HICON supGetMainIcon(
	_In_ LPWSTR lpFileName, 
	_In_ INT cx,
	_In_ INT cy
	)
{
	HMODULE hModule;
	ENUMICONINFO pin;

	pin.cx = cx;
	pin.cy = cy;
	pin.hIcon = 0;

	hModule = LoadLibraryEx(lpFileName, 0, LOAD_LIBRARY_AS_DATAFILE);
	if (hModule != NULL) {
		EnumResourceNames(hModule, RT_GROUP_ICON, (ENUMRESNAMEPROC)&supEnumIconCallback, 
			(LONG_PTR)&pin);
		FreeLibrary(hModule);
	}
	return pin.hIcon;
}

/*
* supCopyMemory
*
* Purpose:
*
* Copies bytes between buffers.
*
* dest - Destination buffer 
* cbdest - Destination buffer size in bytes
* src - Source buffer
* cbsrc - Source buffer size in bytes
*
*/
void supCopyMemory(
	_Inout_ void *dest,
	_In_ size_t cbdest,
	_In_ const void *src,
	_In_ size_t cbsrc
	)
{
	char *d = (char*)dest;
	char *s = (char*)src;

	if ((dest == 0) || (src == 0) || (cbdest == 0))
		return;
	if (cbdest<cbsrc)
		cbsrc = cbdest;

	while (cbsrc>0) {
		*d++ = *s++;
		cbsrc--;
	}
}

/*
* supSetWaitCursor
*
* Purpose:
*
* Sets cursor state.
*
*/
VOID supSetWaitCursor(
	BOOL fSet
	)
{
	ShowCursor(fSet);
	SetCursor(LoadCursor(NULL, fSet ? IDC_WAIT : IDC_ARROW));
}

/*
* supCenterWindow
*
* Purpose:
*
* Centers given window relative to it parent window.
*
*/
VOID supCenterWindow(
	HWND hwnd
	)
{
	RECT rc, rcDlg, rcOwner;
	HWND hwndParent = GetParent(hwnd);

	//center window
	if (hwndParent) {
		GetWindowRect(hwndParent, &rcOwner);
		GetWindowRect(hwnd, &rcDlg);
		CopyRect(&rc, &rcOwner);
		OffsetRect(&rcDlg, -rcDlg.left, -rcDlg.top);
		OffsetRect(&rc, -rc.left, -rc.top);
		OffsetRect(&rc, -rcDlg.right, -rcDlg.bottom);
		SetWindowPos(hwnd,
			HWND_TOP,
			rcOwner.left + (rc.right / 2),
			rcOwner.top + (rc.bottom / 2),
			0, 0,
			SWP_NOSIZE);
	}
}

/*
* supGetSystemInfo
*
* Purpose:
*
* Returns buffer with system information by given InfoClass.
*
* Returned buffer must be freed with HeapFree after usage.
* Function will return error after 100 attempts.
*
*/
PVOID supGetSystemInfo(
	_In_ SYSTEM_INFORMATION_CLASS InfoClass
	)
{
	INT			c = 0;
	PVOID		Buffer = NULL;
	ULONG		Size	= 0x1000;
	NTSTATUS	status;
	ULONG       memIO;

	do {
		Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)Size);
		if (Buffer != NULL) {
			status = NtQuerySystemInformation(InfoClass, Buffer, Size, &memIO);
		}
		else {
			return NULL;
		}
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			HeapFree(GetProcessHeap(), 0, Buffer);
			Size *= 2;
			c++;
			if (c > 100) {
				status = STATUS_SECRET_TOO_LONG;
				break;
			}
		}
	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (NT_SUCCESS(status)) {
		return Buffer;
	}

	if (Buffer) {
		HeapFree(GetProcessHeap(), 0, Buffer);
	}
	return NULL;
}

/*
* supGetObjectTypesInfo
*
* Purpose:
*
* Returns buffer with system types information.
*
* Returned buffer must be freed with HeapFree after usage.
* Function will return error after 100 attempts.
*
*/
PVOID supGetObjectTypesInfo(
	VOID
	)
{
	INT			c = 0;
	PVOID		Buffer = NULL;
	ULONG		Size = 0x1000;
	NTSTATUS	status;
	ULONG       memIO;

	do {
		Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)Size);
		if (Buffer != NULL) {
			status = NtQueryObject(NULL, ObjectTypesInformation, Buffer, Size, &memIO);
		}
		else {
			return NULL;
		}
		if (NT_SUCCESS(status)) {
			break;
		}
		else {
			Size = memIO;
			HeapFree(GetProcessHeap(), 0, Buffer);
			Buffer = NULL;
		}
		c++;
		if (c > 100) {
			status = STATUS_SECRET_TOO_LONG;
			break;
		}
	} while (status != STATUS_SUCCESS);

	if (NT_SUCCESS(status)) {
		return Buffer;
	}

	if (Buffer) {
		HeapFree(GetProcessHeap(), 0, Buffer);
	}
	return NULL;
}

/*
* supGetItemText
*
* Purpose:
*
* Returns buffer with text from the given listview item.
*
* Returned buffer must be freed with HeapFree after usage.
*
*/
LPWSTR supGetItemText(
	_In_ HWND ListView,
	_In_ INT nItem,
	_In_ INT nSubItem,
	_Inout_opt_ PSIZE_T lpSize
	)
{
	LV_ITEM item;
	INT len;
	LPARAM sz;

	RtlSecureZeroMemory(&item, sizeof(item));

	item.iItem = nItem;
	item.iSubItem = nSubItem;
	len = 128;
	do {
		len *= 2;
		item.cchTextMax = len;
		if (item.pszText) {
			HeapFree(GetProcessHeap(), 0, item.pszText);
			item.pszText = NULL;
		}
		item.pszText = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len*sizeof(WCHAR));
		sz = SendMessage(ListView, LVM_GETITEMTEXT, (WPARAM)item.iItem, (LPARAM)&item);
	} while (sz == len - 1);

	//empty string
	if (sz == 0) {
		if (item.pszText) {
			HeapFree(GetProcessHeap(), 0, item.pszText);
			item.pszText = NULL;
		}
	}

	if (lpSize) {
		*lpSize = sz * sizeof(WCHAR);
	}
	return item.pszText;
}

/*
* supLoadImageList
*
* Purpose:
*
* Create and load image list from icon resource type.
*
*/
HIMAGELIST supLoadImageList(
	HINSTANCE hInst,
	UINT FirstId,
	UINT LastId
	)
{
	UINT i;
	HIMAGELIST list;
	HICON hIcon;
	list = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 42, 8);
	if (list) {
		for (i = FirstId; i <= LastId; i++) {
			hIcon = LoadImage(hInst, MAKEINTRESOURCE(i), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
			if (hIcon) {
				ImageList_ReplaceIcon(list, -1, hIcon);
				DestroyIcon(hIcon);
			}
		}
	}
	return list;
}

/*
* supGetObjectNameIndexByTypeIndex
*
* Purpose:
*
* Returns object index of known type.
*
* Known type names listed in sup.c T_ObjectNames, and known object indexes listed in sup.h as TYPE_*
*
*/
UINT supGetObjectNameIndexByTypeIndex(
	_In_ PVOID Object,
	_In_ UCHAR TypeIndex
	)
{
	UINT Index;
	ULONG i;
	BOOL bFound = FALSE;
	POBJECT_TYPE_INFORMATION pObject;
	POBJECT_TYPE_INFORMATION_8 pObject8;

	if (Object == NULL) {
		return TYPE_UNKNOWN;
	}

	Index = ObDecodeTypeIndex(Object, TypeIndex);

	pObject = (POBJECT_TYPE_INFORMATION)&g_pObjectTypesInfo->TypeInformation;
	for (i = 0; i < g_pObjectTypesInfo->NumberOfTypes; i++) {
		
		if (g_kdctx.osver.dwBuildNumber >= 9200) {
			pObject8 = (POBJECT_TYPE_INFORMATION_8)pObject;
			if (pObject8->TypeIndex == Index) {
				bFound = TRUE;
			}
		}
		else {
			if (i + 2 == Index) {
				bFound = TRUE;
			}
		}

		if (bFound) {
			return supGetObjectIndexByTypeName(pObject->TypeName.Buffer);
		}

		pObject = (POBJECT_TYPE_INFORMATION)((PCHAR)(pObject + 1) +
			ALIGN_UP(pObject->TypeName.MaximumLength, sizeof(ULONG_PTR)));
	}

	return TYPE_UNKNOWN;
}


/*
* supGetObjectIndexByTypeName
*
* Purpose:
*
* Returns object index of known type.
*
* Known type names listed in sup.c T_ObjectNames, and known object indexes listed in sup.h as TYPE_*
*
*/
UINT supGetObjectIndexByTypeName(
	_In_ LPCWSTR lpTypeName
	)
{
	UINT nIndex;

	if (lpTypeName == NULL) {
		return TYPE_UNKNOWN;
	}

	for (nIndex = TYPE_DEVICE; nIndex < TYPE_UNKNOWN; nIndex++) {
		if (_strcmpi(lpTypeName, T_ObjectNames[nIndex]) == 0)
			return nIndex;
	}

	//
	// In Win8 the following Win32k object was named 
	// CompositionSurface, in Win8.1 MS renamed it to
	// Composition, handle this.
	//
	if (_strcmpi(lpTypeName, L"CompositionSurface") == 0) {
		return TYPE_COMPOSITION;
	}

	return TYPE_UNKNOWN;
}

/*
* supRunAsAdmin
*
* Purpose:
*
* Restarts application requesting full admin rights.
*
*/
VOID supRunAsAdmin(
	VOID
	)
{
	SHELLEXECUTEINFOW shinfo;
	WCHAR szPath[MAX_PATH + 1];
	RtlSecureZeroMemory(&szPath, sizeof(szPath));
	if (GetModuleFileNameW(NULL, szPath, MAX_PATH)) {
		RtlSecureZeroMemory(&shinfo, sizeof(shinfo));
		shinfo.cbSize = sizeof(shinfo);
		shinfo.lpVerb = L"runas";
		shinfo.lpFile = szPath;
		shinfo.nShow = SW_SHOW;
		if (ShellExecuteExW(&shinfo)) {
			PostQuitMessage(0);
		}
	}
}

/*
* supShowProperties
*
* Purpose:
*
* Show file properties Windows dialog.
*
*/
VOID supShowProperties(
	_In_ HWND hwndDlg,
	_In_ LPWSTR lpFileName
	)
{
	SHELLEXECUTEINFOW shinfo;

	if (lpFileName == NULL) {
		return;
	}

	RtlSecureZeroMemory(&shinfo, sizeof(shinfo));
	shinfo.cbSize = sizeof(shinfo);
	shinfo.fMask = SEE_MASK_INVOKEIDLIST | SEE_MASK_FLAG_NO_UI;
	shinfo.hwnd = hwndDlg; 
	shinfo.lpVerb = L"properties";
	shinfo.lpFile = lpFileName;
	shinfo.nShow = SW_SHOWNORMAL;
	ShellExecuteEx(&shinfo);
}


/*
* supUserIsFullAdmin
*
* Purpose:
*
* Tests if the current user is admin with full access token.
*
*/
BOOL supUserIsFullAdmin(
	VOID
	)
{
	BOOL bResult = FALSE, cond = FALSE;
	HANDLE hToken = NULL;
	NTSTATUS status;
	DWORD i, Attributes;
	ULONG ReturnLength = 0;

	PTOKEN_GROUPS pTkGroups;

	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup = NULL;

	status = NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
	if (!NT_SUCCESS(status))
		return bResult;

	do {
		if (!AllocateAndInitializeSid(
			&NtAuthority,
			2,
			SECURITY_BUILTIN_DOMAIN_RID,
			DOMAIN_ALIAS_RID_ADMINS,
			0, 0, 0, 0, 0, 0,
			&AdministratorsGroup))
			break;

		status = NtQueryInformationToken(hToken, TokenGroups, NULL, 0, &ReturnLength);
		if (status != STATUS_BUFFER_TOO_SMALL)
			break;

		pTkGroups = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)ReturnLength);
		if (pTkGroups == NULL)
			break;

		status = NtQueryInformationToken(hToken, TokenGroups, pTkGroups, ReturnLength, &ReturnLength);
		if (NT_SUCCESS(status)) {
			if (pTkGroups->GroupCount > 0)
				for (i = 0; i < pTkGroups->GroupCount; i++) {
					Attributes = pTkGroups->Groups[i].Attributes;
					if (EqualSid(AdministratorsGroup, pTkGroups->Groups[i].Sid))
						if (
							(Attributes & SE_GROUP_ENABLED) &&
							(!(Attributes & SE_GROUP_USE_FOR_DENY_ONLY))
							)
						{
							bResult = TRUE;
							break;
						}
				}
		}
		HeapFree(GetProcessHeap(), 0, pTkGroups);

	} while (cond);

	if (AdministratorsGroup != NULL) {
		FreeSid(AdministratorsGroup);
	}

	NtClose(hToken);
	return bResult;
}

/*
* supIsSymlink
*
* Purpose:
*
* Tests if the current item type is Symbolic link.
*
*/
BOOL supIsSymlink(
	INT iItem
	)
{
	WCHAR ItemText[MAX_PATH + 1];
	RtlSecureZeroMemory(ItemText, sizeof(ItemText));
	ListView_GetItemText(ObjectList, iItem, 1, ItemText, MAX_PATH);
	return (_strcmpi(ItemText, T_ObjectNames[TYPE_SYMLINK]) == 0);
}

/*
* supHandleTreePopupMenu
*
* Purpose:
*
* Object Tree popup menu builder.
*
*/
VOID supHandleTreePopupMenu(
	HWND hwnd,
	LPPOINT point
	)
{
	HMENU hMenu;

	hMenu = CreatePopupMenu();
	if (hMenu == NULL) return;
	InsertMenu(hMenu, 0, MF_BYCOMMAND, ID_OBJECT_PROPERTIES, T_PROPERTIES);

	supSetMenuIcon(hMenu, ID_OBJECT_PROPERTIES,
		(ULONG_PTR)ImageList_ExtractIcon(g_hInstance, ToolBarMenuImages, 0));

	TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, point->x, point->y, 0, hwnd, NULL);
	DestroyMenu(hMenu);
}

/*
* supHandleObjectPopupMenu
*
* Purpose:
*
* Object List popup menu builder.
*
*/
VOID supHandleObjectPopupMenu(
	HWND hwnd,
	int iItem,
	LPPOINT point
	)
{
	HMENU hMenu;
	UINT uEnable = MF_BYCOMMAND | MF_GRAYED;

	hMenu = CreatePopupMenu();
	if (hMenu == NULL) return;

	InsertMenu(hMenu, 0, MF_BYCOMMAND, ID_OBJECT_PROPERTIES, T_PROPERTIES);

	supSetMenuIcon(hMenu, ID_OBJECT_PROPERTIES,
		(ULONG_PTR)ImageList_ExtractIcon(g_hInstance, ToolBarMenuImages, 0));

	if (supIsSymlink(iItem)) {
		InsertMenu(hMenu, 1, MF_BYCOMMAND, ID_OBJECT_GOTOLINKTARGET, T_GOTOLINKTARGET);
		supSetMenuIcon(hMenu, ID_OBJECT_GOTOLINKTARGET,
			(ULONG_PTR)ImageList_ExtractIcon(g_hInstance, ListViewImages, ID_FROM_VALUE(IDI_ICON_SYMLINK)));
		uEnable &= ~MF_GRAYED;
	}
	EnableMenuItem(GetSubMenu(GetMenu(hwnd), 2), ID_OBJECT_GOTOLINKTARGET, uEnable);

	TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, point->x, point->y, 0, hwnd, NULL);
	DestroyMenu(hMenu);
}

/*
* supSetMenuIcon
*
* Purpose:
*
* Associates icon data with given menu item.
*
*/
VOID supSetMenuIcon(
	HMENU hMenu,
	UINT Item,
	ULONG_PTR IconData
	)
{
	MENUITEMINFOW mii;
	RtlSecureZeroMemory(&mii, sizeof(mii));
	mii.cbSize = sizeof(mii);
	mii.fMask = MIIM_BITMAP | MIIM_DATA;
	mii.hbmpItem = HBMMENU_CALLBACK;
	mii.dwItemData = IconData;
	SetMenuItemInfo(hMenu, Item, FALSE, &mii);
}

/*
* supCreateToolbarButtons
*
* Purpose:
*
* Main window toolbar initialization.
*
*/
VOID supCreateToolbarButtons(
	HWND hWndToolbar
	)
{
	TBBUTTON tbButtons[5];

	RtlSecureZeroMemory(tbButtons, sizeof(tbButtons));

	tbButtons[0].iBitmap = 0;
	tbButtons[0].fsStyle = BTNS_BUTTON;
	tbButtons[0].idCommand = ID_OBJECT_PROPERTIES;
	tbButtons[0].fsState = TBSTATE_ENABLED;

	//separator
	tbButtons[1].fsStyle = BTNS_SEP;
	tbButtons[1].iBitmap = 10;

	tbButtons[2].iBitmap = 1;
	tbButtons[2].fsStyle = BTNS_BUTTON;
	tbButtons[2].idCommand = ID_VIEW_REFRESH;
	tbButtons[2].fsState = TBSTATE_ENABLED;

	//separator
	tbButtons[3].fsStyle = BTNS_SEP;
	tbButtons[3].iBitmap = 10;

	tbButtons[4].iBitmap = 2;
	tbButtons[4].fsStyle = BTNS_BUTTON;
	tbButtons[4].idCommand = ID_FIND_FINDOBJECT;
	tbButtons[4].fsState = TBSTATE_ENABLED;

	SendMessage(hWndToolbar, TB_SETIMAGELIST, 0, (LPARAM)ToolBarMenuImages);
	SendMessageW(hWndToolbar, TB_LOADIMAGES, (WPARAM)IDB_STD_SMALL_COLOR, (LPARAM)HINST_COMMCTRL);

	SendMessage(hWndToolbar, TB_BUTTONSTRUCTSIZE,
		(WPARAM)sizeof(TBBUTTON), 0);
	SendMessage(hWndToolbar, TB_ADDBUTTONS, (WPARAM)4 + 1,
		(LPARAM)&tbButtons);

	SendMessage(hWndToolbar, TB_AUTOSIZE, 0, 0);
}

/*
* supQueryKnownDllsLink
*
* Purpose:
*
* Expand KnownDlls symbolic link.
*
* Only internal use, returns FALSE on any error.
*
*/
BOOL supQueryKnownDllsLink(
	PUNICODE_STRING ObjectName,
	PVOID *lpKnownDllsBuffer
	)
{
	BOOL				bResult;
	HANDLE				hLink;
	SIZE_T				memIO;
	ULONG				bytesNeeded;
	NTSTATUS			status;
	UNICODE_STRING		KnownDlls;
	OBJECT_ATTRIBUTES   Obja;
	LPWSTR				lpDataBuffer = NULL;
	BOOL				cond = FALSE;

	bResult = FALSE;
	hLink = NULL;

	do {
		InitializeObjectAttributes(&Obja, ObjectName, OBJ_CASE_INSENSITIVE, NULL, NULL);
		status = NtOpenSymbolicLinkObject(&hLink, SYMBOLIC_LINK_QUERY, &Obja);
		if (!NT_SUCCESS(status))
			break;

		KnownDlls.Buffer = NULL;
		KnownDlls.Length = 0;
		KnownDlls.MaximumLength = 0;
		bytesNeeded = 0;
		status = NtQuerySymbolicLinkObject(hLink, &KnownDlls, &bytesNeeded);
		if ((status != STATUS_BUFFER_TOO_SMALL) || (bytesNeeded == 0))
			break;

		if (bytesNeeded >= MAX_USTRING) {
			bytesNeeded = MAX_USTRING - sizeof(UNICODE_NULL);
		}

		memIO = bytesNeeded + sizeof(UNICODE_NULL);
		lpDataBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, memIO);
		if (lpKnownDllsBuffer) {
			KnownDlls.Buffer = lpDataBuffer;
			KnownDlls.Length = (USHORT)bytesNeeded;
			KnownDlls.MaximumLength = (USHORT)bytesNeeded + sizeof(UNICODE_NULL);
			bResult = NT_SUCCESS(NtQuerySymbolicLinkObject(hLink, &KnownDlls, NULL));
			if (bResult) {
				if (lpKnownDllsBuffer) {
					*lpKnownDllsBuffer = lpDataBuffer;
				}
			}
		}

	} while (cond);
	if (hLink != NULL) NtClose(hLink);
	return bResult;
}

/*
* supMapNtdllCopy
*
* Purpose:
*
* Load copy of ntdll from disk.
*
*/
VOID supMapNtdllCopy(
	VOID
	)
{
	BOOL cond = FALSE;
	HANDLE hFile = INVALID_HANDLE_VALUE, hFileMapping = NULL;
	PVOID ImagePtr = NULL;
	WCHAR szDllPath[MAX_PATH + 20];

	do {
		
		RtlSecureZeroMemory(szDllPath, sizeof(szDllPath));
		if (GetSystemDirectory(szDllPath, MAX_PATH) == 0)
			break;

		_strcat(szDllPath, TEXT("\\ntdll.dll"));

		hFile = CreateFile(szDllPath, GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
			OPEN_EXISTING, 0, NULL);
		
		if (hFile == INVALID_HANDLE_VALUE)
			break;

		hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
		if (hFileMapping == NULL)
			break;

		ImagePtr = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
		if (ImagePtr == NULL)
			break;

		g_NtdllModule = peldrLoadImage(ImagePtr, NULL);

		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;

	} while (cond);

	if (hFile != INVALID_HANDLE_VALUE) 
		CloseHandle(hFile);

	if (hFileMapping != NULL)
		CloseHandle(hFileMapping);

}

/*
* supInit
*
* Purpose:
*
* Initializes support subset related resources including kldbg subset.
*
* Must be called once during program startup
*
*/
VOID supInit(
	BOOL IsFullAdmin
	)
{
	RtlSecureZeroMemory(&g_enumParams, sizeof(g_enumParams));

	supQueryKnownDlls();
	kdInit(IsFullAdmin);

	if (IsFullAdmin != FALSE) {
		g_enumParams.scmSnapshot = supCreateSCMSnapshot(&g_enumParams.scmNumberOfEntries);
		supMapNtdllCopy();
	}

	g_enumParams.sapiDB = sapiCreateSetupDBSnapshot();

	g_pObjectTypesInfo = supGetObjectTypesInfo();
}

/*
* supShutdown
*
* Purpose:
*
* Free support subset related resources.
*
* Must be called once in the end of program execution.
*
*/
VOID supShutdown(
	VOID
	)
{
	kdShutdown();

	supFreeSCMSnapshot(g_enumParams.scmSnapshot);
	sapiFreeSnapshot(g_enumParams.sapiDB);

	if (g_pObjectTypesInfo) HeapFree(GetProcessHeap(), 0, g_pObjectTypesInfo);

	if (TreeViewImages) ImageList_Destroy(TreeViewImages);
	if (ListViewImages) ImageList_Destroy(ListViewImages);
	if (ToolBarMenuImages) ImageList_Destroy(ToolBarMenuImages);

	if (g_lpKnownDlls32) HeapFree(GetProcessHeap(), 0, g_lpKnownDlls32);
	if (g_lpKnownDlls64) HeapFree(GetProcessHeap(), 0, g_lpKnownDlls64);

	if (g_SdtTable) HeapFree(GetProcessHeap(), 0, g_SdtTable);
	if (g_NtdllModule) {
		VirtualFree(g_NtdllModule, 0, MEM_RELEASE);
	}
}

/*
* supQueryKnownDlls
*
* Purpose:
*
* Expand KnownDlls to global variables.
*
*/
VOID supQueryKnownDlls(
	VOID
	)
{
	UNICODE_STRING		KnownDlls;

	g_lpKnownDlls32 = NULL;
	g_lpKnownDlls64 = NULL;

	RtlSecureZeroMemory(&KnownDlls, sizeof(KnownDlls));
	RtlInitUnicodeString(&KnownDlls, L"\\KnownDlls32\\KnownDllPath");
	supQueryKnownDllsLink(&KnownDlls, &g_lpKnownDlls32);
	RtlInitUnicodeString(&KnownDlls, L"\\KnownDlls\\KnownDllPath");
	supQueryKnownDllsLink(&KnownDlls, &g_lpKnownDlls64);
}

/*
* supEnablePrivilege
*
* Purpose:
*
* Enable/Disable given privilege.
*
* Return FALSE on any error.
*
*/
BOOL supEnablePrivilege(
	_In_ DWORD	PrivilegeName,
	_In_ BOOL	fEnable
	)
{
	BOOL bResult = FALSE;
	NTSTATUS status;
	HANDLE hToken;
	TOKEN_PRIVILEGES TokenPrivileges;

	status = NtOpenProcessToken(
		GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken);

	if (!NT_SUCCESS(status)) {
		return bResult;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Luid.LowPart = PrivilegeName;
	TokenPrivileges.Privileges[0].Luid.HighPart = 0;
	TokenPrivileges.Privileges[0].Attributes = (fEnable) ? SE_PRIVILEGE_ENABLED : 0;
	status = NtAdjustPrivilegesToken(hToken, FALSE, &TokenPrivileges,
		sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, NULL);
	if (status == STATUS_NOT_ALL_ASSIGNED) {
		status = STATUS_PRIVILEGE_NOT_HELD;
	}
	bResult = NT_SUCCESS(status);
	NtClose(hToken);
	return bResult;
}

/*
* supQueryLinkTarget
*
* Purpose:
*
* Copying in the input buffer target of a symbolic link.
*
* Return FALSE on any error.
*
*/
BOOL supQueryLinkTarget(
	_In_opt_	HANDLE hRootDirectory,
	_In_		PUNICODE_STRING ObjectName,
	_Inout_		LPWSTR Buffer,
	_In_		DWORD cbBuffer //size of buffer in bytes
	)
{
	BOOL				bResult = FALSE;
	HANDLE				hLink = NULL;
	DWORD				cLength = 0;
	NTSTATUS			status;
	UNICODE_STRING		InfoString;
	OBJECT_ATTRIBUTES   Obja;

	if (
		(ObjectName == NULL) ||
		(Buffer == NULL) ||
		(cbBuffer < sizeof(UNICODE_NULL))
		)
	{
		return bResult;
	}

	InitializeObjectAttributes(&Obja, ObjectName, OBJ_CASE_INSENSITIVE, hRootDirectory, NULL);
	status = NtOpenSymbolicLinkObject(&hLink, SYMBOLIC_LINK_QUERY, &Obja);
	if (!NT_SUCCESS(status) || (hLink == NULL)) {
		return bResult;
	}

	cLength = (cbBuffer - sizeof(UNICODE_NULL));
	if (cLength >= MAX_USTRING) {
		cLength = MAX_USTRING - sizeof(UNICODE_NULL);
	}

	InfoString.Buffer = Buffer;
	InfoString.Length = (USHORT)cLength;
	InfoString.MaximumLength = (USHORT)(cLength + sizeof(UNICODE_NULL));

	status = NtQuerySymbolicLinkObject(hLink, &InfoString, NULL);
	bResult = (NT_SUCCESS(status));
	NtClose(hLink);
	return bResult;
}

/*
* supQueryProcessName
*
* Purpose:
*
* Lookups process name by given process ID.
*
* If nothing found return FALSE.
*
*/
BOOL supQueryProcessName(
	_In_		DWORD dwProcessId,
	_In_		PVOID ProcessList,
	_Inout_		LPWSTR Buffer,
	_In_		DWORD ccBuffer //size of buffer in chars
	)
{
	PSYSTEM_PROCESSES_INFORMATION pList = ProcessList;

	if ((ProcessList == NULL) || (Buffer == NULL) || (ccBuffer == 0))
		return FALSE;

	for (;;) {
		if ((DWORD)pList->UniqueProcessId == dwProcessId) {		
			_strncpy(Buffer, ccBuffer, pList->ImageName.Buffer, pList->ImageName.Length / sizeof(WCHAR));
			return TRUE;
		}
		if (pList->NextEntryDelta == 0)
			break;
		pList = (PSYSTEM_PROCESSES_INFORMATION)(((LPBYTE)pList) + pList->NextEntryDelta);
	}
	return FALSE;
}

/*
* supFreeScmSnapshot
*
* Purpose:
*
* Releases SCM snapshot allocated memory.
*
*/
VOID supFreeSCMSnapshot(
	_In_ PVOID Snapshot
	)
{
	if (Snapshot) {
		VirtualFree(Snapshot, 0, MEM_RELEASE);
	}
}

/*
* supCreateSCMSnapshot
*
* Purpose:
*
* Collects SCM information for drivers description.
*
* Returned buffer must be freed with supFreeScmSnapshot after usage.
*
*/
PVOID supCreateSCMSnapshot(
	PSIZE_T lpNumberOfEntries
	)
{
	BOOL cond = FALSE, bResult = FALSE;
	SC_HANDLE schSCManager;
	DWORD dwBytesNeeded, dwServicesReturned, dwSize, dwSlack;
	PVOID Services = NULL;

	if (lpNumberOfEntries) {
		*lpNumberOfEntries = 0;
	}

	do {
		schSCManager = OpenSCManager(NULL,
			NULL,
			SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE
			);

		if (schSCManager == NULL) {
			break;
		}

		// query required memory size for snapshot
		dwBytesNeeded = 0;
		dwServicesReturned = 0;

		dwSize = 0x1000;
		Services = VirtualAlloc(NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (Services == NULL) {
			break;
		}
		
		bResult = EnumServicesStatusEx(schSCManager, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, 
			SERVICE_STATE_ALL, Services, dwSize, &dwBytesNeeded, &dwServicesReturned, NULL, NULL);	
		if (bResult == FALSE) {

			if (GetLastError() == ERROR_MORE_DATA) {
				// allocate memory block with page aligned size
				VirtualFree(Services, 0, MEM_RELEASE);
				dwSize = dwBytesNeeded + sizeof(ENUM_SERVICE_STATUS_PROCESS);
				dwSlack = dwSize % 0x1000;
				if (dwSlack > 0) dwSize = dwSize + 0x1000 - dwSlack;

				Services = VirtualAlloc(NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				if (Services == NULL) {
					break;
				}

				if (!EnumServicesStatusEx(schSCManager, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, 
					SERVICE_STATE_ALL, Services, dwSize, &dwBytesNeeded, &dwServicesReturned, NULL, NULL)) 
				{
					VirtualFree(Services, 0, MEM_RELEASE);
					Services = NULL;
					break;
				}
			} //ERROR_MORE_DATA
		} //bResult == FALSE;

		// also return actual number of services
		if (lpNumberOfEntries) {
			*lpNumberOfEntries = dwServicesReturned;
		}

		CloseServiceHandle(schSCManager);
	} while (cond);

	return Services;
}

/*
* sapiCreateSetupDBSnapshot
*
* Purpose:
*
* Collects Setup API information to the linked list.
*
* Returned buffer must be freed with sapiFreeSnapshot after usage.
*
*/
PVOID sapiCreateSetupDBSnapshot(
	VOID
	)
{
	BOOL cond = FALSE;
	PSAPIDBOBJ sObj;
	SP_DEVINFO_DATA DeviceInfoData;
	DWORD i, DataType = 0;
	DWORD DataSize, ReturnedDataSize = 0;
	PSAPIDBENTRY Entry;

	sObj = VirtualAlloc(NULL, sizeof(SAPIDBOBJ), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (sObj == NULL)
		return NULL;

	sObj->hDevInfo = NULL;
	sObj->sapiDBHead.Blink = NULL;
	sObj->sapiDBHead.Flink = NULL;
	InitializeCriticalSection(&sObj->objCS);

	do {
		sObj->hDevInfo = SetupDiGetClassDevsW(NULL, NULL, NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES);

		if (sObj->hDevInfo == INVALID_HANDLE_VALUE)
			break;

		InitializeListHead(&sObj->sapiDBHead);

		DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
		for (i = 0; SetupDiEnumDeviceInfo(sObj->hDevInfo, i, &DeviceInfoData); i++) {

			Entry = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SAPIDBENTRY));
			if (Entry == NULL)
				break;

			// first query lpDeviceName
			DataSize = MAX_PATH * sizeof(WCHAR);
			Entry->lpDeviceName = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DataSize);
			if (Entry->lpDeviceName != NULL) {
				SetupDiGetDeviceRegistryPropertyW(sObj->hDevInfo,
					&DeviceInfoData,
					SPDRP_PHYSICAL_DEVICE_OBJECT_NAME,
					&DataType,
					(PBYTE)Entry->lpDeviceName,
					DataSize,
					&ReturnedDataSize);

				// not enough memory for call, reallocate
				if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {

					HeapFree(GetProcessHeap(), 0, Entry->lpDeviceName);
					Entry->lpDeviceName = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ReturnedDataSize);
					if (Entry->lpDeviceName != NULL) {
						 SetupDiGetDeviceRegistryPropertyW(sObj->hDevInfo,
							&DeviceInfoData,
							SPDRP_PHYSICAL_DEVICE_OBJECT_NAME,
							&DataType,
							(PBYTE)Entry->lpDeviceName,
							ReturnedDataSize,
							&ReturnedDataSize);
					}
				}
			}

			DataSize = MAX_PATH * sizeof(WCHAR);
			Entry->lpDeviceDesc = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DataSize);
			if (Entry->lpDeviceDesc != NULL) {
				SetupDiGetDeviceRegistryPropertyW(sObj->hDevInfo,
					&DeviceInfoData,
					SPDRP_DEVICEDESC,
					&DataType,
					(PBYTE)Entry->lpDeviceDesc,
					DataSize,
					&ReturnedDataSize);

				// not enough memory for call, reallocate
				if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {

					HeapFree(GetProcessHeap(), 0, Entry->lpDeviceDesc);
					Entry->lpDeviceDesc = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ReturnedDataSize);
					if (Entry->lpDeviceDesc != NULL) {
						SetupDiGetDeviceRegistryPropertyW(sObj->hDevInfo,
							&DeviceInfoData,
							SPDRP_DEVICEDESC,
							&DataType,
							(PBYTE)Entry->lpDeviceDesc,
							ReturnedDataSize,
							&ReturnedDataSize);
					}
				}
			}	
			InsertHeadList(&sObj->sapiDBHead, &Entry->ListEntry);
		} //for

	} while (cond);

	return sObj;
}

/*
* sapiFreeSnapshot
*
* Purpose:
*
* Releases memory allocated for Setup API snapshot and linked list.
*
*/
VOID sapiFreeSnapshot(
	_In_ PVOID Snapshot
	)
{
	PSAPIDBOBJ pObj;
	PSAPIDBENTRY Entry;

	if (Snapshot == NULL)
		return;

	pObj = Snapshot;

	EnterCriticalSection(&pObj->objCS);

	if (pObj->hDevInfo != NULL) {
		SetupDiDestroyDeviceInfoList(pObj->hDevInfo);
	}

	while (!IsListEmpty(&pObj->sapiDBHead)) {
		if (pObj->sapiDBHead.Flink == NULL) break;
		Entry = CONTAINING_RECORD(pObj->sapiDBHead.Flink, SAPIDBENTRY, ListEntry);
		RemoveEntryList(pObj->sapiDBHead.Flink);
		if (Entry) {
			if (Entry->lpDeviceDesc) HeapFree(GetProcessHeap(), 0, Entry->lpDeviceDesc);
			if (Entry->lpDeviceName) HeapFree(GetProcessHeap(), 0, Entry->lpDeviceName);
			HeapFree(GetProcessHeap(), 0, Entry);
		}
	}

	LeaveCriticalSection(&pObj->objCS);
	DeleteCriticalSection(&pObj->objCS);
	VirtualFree(pObj, 0, MEM_RELEASE);
}

/*
* supEnumEnableChildWindows
*
* Purpose:
*
* Makes window controls visible in the given rectangle type dialog
*
*/
BOOL WINAPI supEnumEnableChildWindows(
	_In_  HWND hwnd,
	_In_  LPARAM lParam
	)
{
	RECT r1;
	LPRECT lpRect = (LPRECT)lParam;

	if (GetWindowRect(hwnd, &r1)) {
		if (PtInRect(lpRect, *(POINT*)&r1))
			ShowWindow(hwnd, SW_SHOW);
	}
	return TRUE;
}

/*
* supEnumHideChildWindows
*
* Purpose:
*
* Makes window controls invisible in the given rectangle type dialog
*
*/
BOOL WINAPI supEnumHideChildWindows(
	_In_  HWND hwnd,
	_In_  LPARAM lParam
	)
{
	RECT r1;
	LPRECT lpRect = (LPRECT)lParam;

	if (GetWindowRect(hwnd, &r1)) {
		if (PtInRect(lpRect, *(POINT*)&r1))
			ShowWindow(hwnd, SW_HIDE);
	}
	return TRUE;
}

#define T_WINSTA_SYSTEM L"-0x0-3e7$"
#define T_WINSTA_ANONYMOUS L"-0x0-3e6$"
#define T_WINSTA_LOCALSERVICE L"-0x0-3e5$"
#define T_WINSTA_NETWORK_SERVICE L"-0x0-3e4$"

/*
* supQueryWinstationDescription
*
* Purpose:
*
* Query predefined window station types, if found equal copy to buffer it friendly name.
*
* Input buffer size must be at least MAX_PATH size.
*
*/
BOOL supQueryWinstationDescription(
	_In_	LPWSTR lpWindowStationName,
	_Inout_	LPWSTR Buffer,
	_In_	DWORD ccBuffer //size of buffer in chars
	)
{
	BOOL bFound = FALSE;
	LPWSTR lpType;

	if ((lpWindowStationName == NULL) || (Buffer == NULL) || (ccBuffer < MAX_PATH))
		return bFound;
	
	lpType = NULL;
	if (_strstri(lpWindowStationName, T_WINSTA_SYSTEM) != NULL) {
		lpType = L"System";
		bFound = TRUE;
		goto Done;
	}
	if (_strstri(lpWindowStationName, T_WINSTA_ANONYMOUS) != NULL) {
		lpType = L"Anonymous";
		bFound = TRUE;
		goto Done;
	}
	if (_strstri(lpWindowStationName, T_WINSTA_LOCALSERVICE) != NULL) {
		lpType = L"Local Service";
		bFound = TRUE;
		goto Done;
	}
	if (_strstri(lpWindowStationName, T_WINSTA_NETWORK_SERVICE) != NULL) {
		lpType = L"Network Service";
		bFound = TRUE;
	}
Done:
	if (bFound) {
		wsprintf(Buffer, L"%s logon session", lpType);
	}
	return bFound;
}

/*
* supFindModuleEntryByAddress
*
* Purpose:
*
* Find Module Name for given Address.
*
*/
ULONG supFindModuleEntryByAddress(
	_In_	PRTL_PROCESS_MODULES pModulesList,
	_In_	PVOID Address
	)
{
	ULONG i, c;

	if (
		(Address == NULL) ||
		(pModulesList == NULL)
		)
	{
		return (ULONG)-1;
	}

	c = pModulesList->NumberOfModules;
	if (c == 0) {
		return (ULONG)-1;
	}

	for (i = 0; i < c; i++) {
		if (
			IN_REGION(Address,
				pModulesList->Modules[i].ImageBase,
				pModulesList->Modules[i].ImageSize)
			)
		{
			return i;
		}
	}
	return (ULONG)-1;
}


/*
* supFindModuleNameByAddress
*
* Purpose:
*
* Find Module Name for given Address.
*
*/
BOOL supFindModuleNameByAddress(
	_In_	PRTL_PROCESS_MODULES pModulesList,
	_In_	PVOID Address,
	_Inout_	LPWSTR Buffer,
	_In_	DWORD ccBuffer //size of buffer in chars
	)
{
	ULONG i, c;
	PRTL_PROCESS_MODULE_INFORMATION pModule;
	WCHAR szBuffer[MAX_PATH + 1];

	if (
		(Address == NULL) || 
		(pModulesList == NULL) || 
		(Buffer == NULL) || 
		(ccBuffer < MAX_PATH)
		) 
	{
		return FALSE;
	}

	c = pModulesList->NumberOfModules;
	if (c == 0) {
		return FALSE;
	}

	for (i = 0; i < c; i++) {
		if (
			IN_REGION(Address,
			pModulesList->Modules[i].ImageBase,
			pModulesList->Modules[i].ImageSize)
			)
		{
			pModule = &pModulesList->Modules[i];

			RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));

			if (
				MultiByteToWideChar(CP_ACP, 0,
				(LPCSTR)&pModule->FullPathName[pModule->OffsetToFileName],
				sizeof(pModule->FullPathName), 
				szBuffer, 
				MAX_PATH)
				) 
			{
				_strncpy(Buffer, ccBuffer, szBuffer, _strlen(szBuffer));
				return TRUE;
			}
			else { //MultiByteToWideChar error
				return FALSE;
			}
		}
	}
	return FALSE;
}

#include "propDlg.h"
#include "propTypeConsts.h"

/*
* supQueryTypeInfo
*
* Purpose:
*
* Query specific type info for output in listview.
*
*/
BOOL supQueryTypeInfo(
	_In_	LPWSTR lpTypeName, 
	_Inout_	LPWSTR Buffer,
	_In_	DWORD ccBuffer //size of buffer in chars
	)
{
	BOOL bResult = FALSE;
	ULONG i, nPool;
	POBJECT_TYPE_INFORMATION pObject;

	if ((g_pObjectTypesInfo == NULL) || (Buffer == NULL) ) {
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return bResult;
	}
	if (ccBuffer < MAX_PATH) {
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return bResult;
	}

	pObject = (POBJECT_TYPE_INFORMATION)&g_pObjectTypesInfo->TypeInformation;
	for (i = 0; i < g_pObjectTypesInfo->NumberOfTypes; i++) {


	/*	Warning: Dxgk objects missing in this enum in Windows 10 TP
	
		WCHAR test[1000];
		RtlSecureZeroMemory(&test, sizeof(test));
		wsprintfW(test, L"\nLength=%lx, MaxLen=%lx \n", pObject->TypeName.Length, pObject->TypeName.MaximumLength);
		OutputDebugString(test);
		_strncpy(test, MAX_PATH, pObject->TypeName.Buffer, pObject->TypeName.MaximumLength);
		OutputDebugString(test);*/

		if (_strncmpi(pObject->TypeName.Buffer, lpTypeName, pObject->TypeName.Length / sizeof(WCHAR)) == 0) {
			for (nPool = 0; nPool < MAX_KNOWN_POOL_TYPES; nPool++) {
				if ((POOL_TYPE)pObject->PoolType == (POOL_TYPE)a_PoolTypes[nPool].dwValue) {

					_strncpy(
						Buffer, ccBuffer, 
						a_PoolTypes[nPool].lpDescription, 
						_strlen(a_PoolTypes[nPool].lpDescription)
						);

					break;

				}
			}
			bResult = TRUE;
		}
		if (bResult) {
			break;
		}
		//next entry located after the aligned type name buffer
		pObject = (POBJECT_TYPE_INFORMATION)((PCHAR)(pObject + 1) +
			ALIGN_UP(pObject->TypeName.MaximumLength, sizeof(ULONG_PTR)));
	}
	return bResult;
}

/*
* supQueryDeviceDescription
*
* Purpose:
*
* Query device description from Setup API DB dump
*
*/
BOOL supQueryDeviceDescription(
	_In_	LPWSTR lpDeviceName,
	_In_	PVOID Snapshot,
	_Inout_	LPWSTR Buffer,
	_In_	DWORD ccBuffer //size of buffer in chars
	)
{
	BOOL bResult, bIsRoot;
	SIZE_T Length;
	LPWSTR lpFullDeviceName;
	PSAPIDBOBJ pObj;

	PLIST_ENTRY Entry;
	PSAPIDBENTRY Item;

	bResult = FALSE;
	if (
		(lpDeviceName == NULL) ||
		(Buffer == NULL) || 
		(ccBuffer == 0) ||
		(Snapshot == NULL)
		) 
	{
		return bResult;
	}

	pObj = Snapshot;

	EnterCriticalSection(&pObj->objCS);

	lpFullDeviceName = NULL;

	Length = (_strlen(lpDeviceName) * sizeof(WCHAR)) +
		(_strlen(CurrentObjectPath) * sizeof(WCHAR)) + (2 * sizeof(WCHAR)) + sizeof(UNICODE_NULL);

	lpFullDeviceName = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Length);
	if (lpFullDeviceName != NULL) {
	
		// create full path device name for comparison
		_strcpy(lpFullDeviceName, CurrentObjectPath);
		bIsRoot = (_strcmpi(CurrentObjectPath, L"\\") == 0);
		if (bIsRoot == FALSE) {
			_strcat(lpFullDeviceName, L"\\");
		}
		_strcat(lpFullDeviceName, lpDeviceName);

		// enumerate devices
		Entry = pObj->sapiDBHead.Flink;
		while (Entry && Entry != &pObj->sapiDBHead) {
			Item = CONTAINING_RECORD(Entry, SAPIDBENTRY, ListEntry);
			if (Item != NULL) {
				if (Item->lpDeviceName != NULL) {
					if (_strcmpi(lpFullDeviceName, Item->lpDeviceName) == 0) {
						if (Item->lpDeviceDesc != NULL) {
							_strncpy(Buffer, ccBuffer, Item->lpDeviceDesc, _strlen(Item->lpDeviceDesc));
						}
						bResult = TRUE;
						break;
					}
				}
			}
			Entry = Entry->Flink;
		}
		HeapFree(GetProcessHeap(), 0, lpFullDeviceName);
	}

	LeaveCriticalSection(&pObj->objCS);
	return bResult;
}

/*
* supQueryDriverDescription
*
* Purpose:
*
* Query driver description from SCM dump or from file version info
*
*/
BOOL supQueryDriverDescription(
	_In_	LPWSTR lpDriverName,
	_In_	PVOID scmSnapshot,
	_In_	SIZE_T scmNumberOfEntries,
	_Inout_	LPWSTR Buffer,
	_In_	DWORD ccBuffer //size of buffer in chars
	)
{
	BOOL bResult, cond = FALSE;
	LPWSTR lpServiceName = NULL;
	LPWSTR lpDisplayName = NULL;
	LPENUM_SERVICE_STATUS_PROCESS pInfo = NULL;
	SIZE_T i, sz;

	LPTRANSLATE	lpTranslate = NULL;
	PVOID vinfo = FALSE;
	DWORD dwSize, dwHandle;
	LRESULT lRet;
	HKEY hKey = NULL;
	WCHAR szBuffer[MAX_PATH * 2];
	WCHAR szImagePath[MAX_PATH + 1];

	bResult = FALSE;
	if (
		(lpDriverName == NULL) ||
		(Buffer == NULL) ||
		(ccBuffer == 0)
		)
	{
		return bResult;
	}

	// first attempt - look in SCM database
	if (scmSnapshot != NULL) {
		pInfo = (LPENUM_SERVICE_STATUS_PROCESS)scmSnapshot;
		for (i = 0; i < scmNumberOfEntries; i++){

			lpServiceName = pInfo[i].lpServiceName;
			if (lpServiceName == NULL) {
				continue;
			}

			// not our driver - skip
			if (_strcmpi(lpServiceName, lpDriverName) != 0) {
				continue;
			}

			lpDisplayName = pInfo[i].lpDisplayName;
			if (lpDisplayName == NULL) {
				continue;
			}

			// driver has the same name as service - skip, there is no description available
			if (_strcmpi(lpDisplayName, lpDriverName) == 0) {
				continue;
			}

			sz = _strlen(lpDisplayName);
			_strncpy(Buffer, ccBuffer, lpDisplayName, sz);
			bResult = TRUE;
			break;
		}
	}
	
	// second attempt - query through registry and fs
	if (bResult == FALSE) {
	
		do {

			RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
			wsprintfW(szBuffer, REGISTRYSERVICESKEY, lpDriverName);

			hKey = NULL;
			lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, szBuffer, 0, KEY_QUERY_VALUE, &hKey);
			if (ERROR_SUCCESS != lRet) {
				break;
			}

			RtlSecureZeroMemory(szImagePath, sizeof(szImagePath));
			dwSize = sizeof(szImagePath) - sizeof(UNICODE_NULL);
			lRet = RegQueryValueEx(hKey, L"ImagePath", NULL, NULL, (LPBYTE)szImagePath, &dwSize);
			RegCloseKey(hKey);

			if (ERROR_SUCCESS == lRet) {

				dwHandle = 0;
				dwSize = GetFileVersionInfoSize(szImagePath, &dwHandle);
				if (dwSize == 0) {
					break;
				}

				// allocate memory for version_info structure
				vinfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
				if (vinfo == NULL) {
					break;
				}

				// query it from file
				if (!GetFileVersionInfo(szImagePath, 0, dwSize, vinfo)) {
					break;
				}

				// query codepage and language id info
				dwSize = 0;
				if (!VerQueryValue(vinfo, VERSION_TRANSLATION, &lpTranslate, (PUINT)&dwSize)) {
					break;
				}
				if (dwSize == 0) {
					break;
				}

				// query filedescription from file with given codepage & language id
				RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
				wsprintf(szBuffer, VERSION_DESCRIPTION,
					lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);

				// finally query pointer to version_info filedescription block data
				lpDisplayName = NULL;
				dwSize = 0;
				bResult = VerQueryValue(vinfo, szBuffer, &lpDisplayName, (PUINT)&dwSize);
				if (bResult) {
					_strncpy(Buffer, ccBuffer, lpDisplayName, dwSize);
				}
				HeapFree(GetProcessHeap(), 0, vinfo);
			}

		} while (cond);
	}
	return bResult;
}

/*
* supQuerySectionFileInfo
*
* Purpose:
*
* Query section object type File + Image description from version info block
*
*/
BOOL supQuerySectionFileInfo(
	_In_opt_	HANDLE hRootDirectory,
	_In_		PUNICODE_STRING ObjectName,
	_Inout_		LPWSTR Buffer,
	_In_		DWORD ccBuffer //size of buffer in chars
	)
{
	HANDLE						hSection;
	PVOID						vinfo;
	LPWSTR						pcValue, lpszFileName, lpszKnownDlls;
	LPTRANSLATE					lpTranslate;
	SIZE_T						cLength = 0;
	NTSTATUS					status;
	DWORD						dwHandle = 0, dwSize, dwInfoSize;
	BOOL						bResult, cond = FALSE;
	OBJECT_ATTRIBUTES			Obja;
	SECTION_BASIC_INFORMATION	sbi;
	SECTION_IMAGE_INFORMATION	sii;
	WCHAR						szQueryBlock[MAX_PATH];

	bResult = FALSE;
	if (
		(ObjectName == NULL) ||
		(Buffer == NULL) ||
		(ccBuffer == 0)
		)
	{
		return bResult;
	}

	vinfo = NULL;
	lpszFileName = NULL;
	hSection = NULL;
	lpszKnownDlls = NULL;

	do {
		//oleaut32.dll does not have FileDescription

		//  open section with query access
		InitializeObjectAttributes(&Obja, ObjectName, OBJ_CASE_INSENSITIVE, hRootDirectory, NULL);
		status = NtOpenSection(&hSection, SECTION_QUERY, &Obja);
		if (!NT_SUCCESS(status))
			break;

		//  query section flags
		RtlSecureZeroMemory(&sbi, sizeof(sbi));
		status = NtQuerySection(hSection, SectionBasicInformation, (PVOID)&sbi, sizeof(sbi), &cLength);
		if (!NT_SUCCESS(status))
			break;

		//  check if section is SEC_IMAGE | SEC_FILE
		if (!((sbi.AllocationAttributes & SEC_IMAGE) && (sbi.AllocationAttributes & SEC_FILE)))
			break;

		// check image machine type
		RtlSecureZeroMemory(&sii, sizeof(sii));
		status = NtQuerySection(hSection, SectionImageInformation, (PVOID)&sii, sizeof(sii), &cLength);
		if (!NT_SUCCESS(status))
			break;

		// select proper decoded KnownDlls path
		if (sii.Machine == IMAGE_FILE_MACHINE_I386) {
			lpszKnownDlls = g_lpKnownDlls32;
		}
		else if (sii.Machine == IMAGE_FILE_MACHINE_AMD64) {
			lpszKnownDlls = g_lpKnownDlls64;
		}

		// paranoid
		if (lpszKnownDlls == NULL) {
			RtlSecureZeroMemory(szQueryBlock, sizeof(szQueryBlock));
			GetSystemDirectory(szQueryBlock, MAX_PATH);
			lpszKnownDlls = szQueryBlock;
		}

		// allocate memory buffer to store full filename
		// KnownDlls + \\ + Object->Name + \0 
		cLength = (_strlen(lpszKnownDlls) * sizeof(WCHAR)) +
			(_strlen(ObjectName->Buffer) * sizeof(WCHAR)) + 2 * sizeof(WCHAR);

		lpszFileName = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cLength);
		if (lpszFileName == NULL)
			break;

		// construct target filepath
		_strcpy(lpszFileName, lpszKnownDlls);
		_strcat(lpszFileName, L"\\");
		_strcat(lpszFileName, ObjectName->Buffer);

		// query size of version info
		dwSize = GetFileVersionInfoSize(lpszFileName, &dwHandle);
		if (dwSize == 0)
			break;

		// allocate memory for version_info structure
		vinfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
		if (vinfo == NULL)
			break;

		// query it from file
		if (!GetFileVersionInfo(lpszFileName, 0, dwSize, vinfo))
			break;

		// query codepage and language id info
		if (!VerQueryValue(vinfo, VERSION_TRANSLATION, &lpTranslate, (PUINT)&dwInfoSize))
			break;
		if (dwInfoSize == 0)
			break;

		// query filedescription from file with given codepage & language id
		RtlSecureZeroMemory(szQueryBlock, sizeof(szQueryBlock));
		wsprintf(szQueryBlock, VERSION_DESCRIPTION,
			lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);
		
		// finally query pointer to version_info filedescription block data
		pcValue = NULL;
		dwInfoSize = 0;
		bResult = VerQueryValue(vinfo, szQueryBlock, &pcValue, (PUINT)&dwInfoSize);
		if (bResult) {
			_strncpy(Buffer, ccBuffer, pcValue, dwInfoSize);
		}

	} while (cond);

	if (hSection) NtClose(hSection);
	if (vinfo) HeapFree(GetProcessHeap(), 0, vinfo);
	if (lpszFileName) HeapFree(GetProcessHeap(), 0, lpszFileName);
	return bResult;
}

/*
* supOpenDirectory
*
* Purpose:
*
* Open directory handle with DIRECTORY_QUERY access
*
*/
HANDLE supOpenDirectory(
	_In_ LPWSTR lpDirectory
	)
{
	HANDLE hDirectory;
	UNICODE_STRING ustr;
	OBJECT_ATTRIBUTES obja;

	if (lpDirectory == NULL) {
		return NULL;
	}
	RtlSecureZeroMemory(&ustr, sizeof(ustr));
	RtlInitUnicodeString(&ustr, lpDirectory);
	InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);

	hDirectory = NULL;
	NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &obja);

	return hDirectory;
}

/*
* supOpenDirectoryForObject
*
* Purpose:
*
* Open directory for given object, handle self case
*
*/
HANDLE supOpenDirectoryForObject(
	_In_ LPWSTR lpObjectName,
	_In_ LPWSTR lpDirectory
	)
{
	HANDLE hDirectory;
	SIZE_T i, l, rdirLen, ldirSz;
	LPWSTR SingleDirName, LookupDirName;
	BOOL needFree = FALSE;

	if (
		(lpObjectName == NULL) ||
		(lpDirectory == NULL)
		) 
	{
		return NULL;
	}

	LookupDirName = lpDirectory;

	//
	// 1) Check if object is directory self
	// Extract directory name and compare (case insensitive) with object name
	// Else go to 3
	//
	l = 0;
	rdirLen = _strlen(lpDirectory);
	for (i = 0; i < rdirLen; i++) {
		if (lpDirectory[i] == '\\')
			l = i + 1;
	}
	SingleDirName = &lpDirectory[l];
	if (_strcmpi(SingleDirName, lpObjectName) == 0) {
		//
		//  2) If we are looking for directory, move search directory up
		//  e.g. lpDirectory = \ObjectTypes, lpObjectName = ObjectTypes then lpDirectory = \ 
		//
		ldirSz = rdirLen * sizeof(WCHAR) + sizeof(UNICODE_NULL);
		LookupDirName = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ldirSz);
		if (LookupDirName == NULL)
			return NULL;

		needFree = TRUE;

		//special case for root 
		if (l == 1) l++;
	
		supCopyMemory(LookupDirName, ldirSz, lpDirectory, (l - 1) * sizeof(WCHAR));
	}
	//
	// 3) Open directory
	//
	hDirectory = supOpenDirectory(LookupDirName);

	if (needFree) {
		HeapFree(GetProcessHeap(), 0, LookupDirName);
	}

	return hDirectory;
}

/*
* supSaveDialogExecute
*
* Purpose:
*
* Display SaveDialog
*
*/
BOOL supSaveDialogExecute(
	_In_ HWND OwnerWindow,
	_Inout_ LPWSTR SaveFileName,
	_In_ LPWSTR lpDialogFilter
	)
{
	OPENFILENAMEW tag1;

	RtlSecureZeroMemory(&tag1, sizeof(OPENFILENAMEW));

	tag1.lStructSize = sizeof(OPENFILENAMEW);
	tag1.hwndOwner = OwnerWindow;
	tag1.lpstrFilter = lpDialogFilter;
	tag1.lpstrFile = SaveFileName;
	tag1.nMaxFile = MAX_PATH;
	tag1.lpstrInitialDir = NULL;
	tag1.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;

	return GetSaveFileNameW(&tag1);
}

/*
* supWriteBufferToFile
*
* Purpose:
*
* Create new file and write buffer to it.
*
*/
ULONG_PTR supWriteBufferToFile(
	_In_ PWSTR lpFileName,
	_In_ PVOID Buffer,
	_In_ SIZE_T Size,
	_In_ BOOL Flush,
	_In_ BOOL Append
	)
{
	NTSTATUS Status;
	DWORD dwFlag;
	HANDLE hFile = NULL;
	OBJECT_ATTRIBUTES attr;
	UNICODE_STRING NtFileName;
	IO_STATUS_BLOCK IoStatus;
	LARGE_INTEGER Position;
	ACCESS_MASK DesiredAccess;
	PLARGE_INTEGER pPosition = NULL;

	ULONG_PTR nBlocks, BlockIndex, BytesWritten = 0;
	ULONG BlockSize, RemainingSize;
	PBYTE ptr = (PBYTE)Buffer;

	if (RtlDosPathNameToNtPathName_U(lpFileName, &NtFileName, NULL, NULL) == FALSE)
		return 0;

	DesiredAccess = FILE_WRITE_ACCESS | SYNCHRONIZE;
	dwFlag = FILE_OVERWRITE_IF;

	if (Append == TRUE) {
		DesiredAccess |= FILE_READ_ACCESS;
		dwFlag = FILE_OPEN_IF;
	}

	InitializeObjectAttributes(&attr, &NtFileName, OBJ_CASE_INSENSITIVE, 0, NULL);

	__try {
		Status = NtCreateFile(&hFile, DesiredAccess, &attr,
			&IoStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, dwFlag,
			FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

		if (!NT_SUCCESS(Status))
			__leave;

		pPosition = NULL;

		if (Append == TRUE) {
			Position.LowPart = 0xFFFFFFFF;
			Position.HighPart = -1;
			pPosition = &Position;
		}

		BlockSize = 0x7FFFFFFF;
		nBlocks = (Size / BlockSize);
		for (BlockIndex = 0; BlockIndex < nBlocks; BlockIndex++) {

			Status = NtWriteFile(hFile, 0, NULL, NULL, &IoStatus, ptr, BlockSize, pPosition, NULL);
			if (!NT_SUCCESS(Status))
				__leave;

			ptr += BlockSize;
			BytesWritten += IoStatus.Information;
		}
		RemainingSize = Size % BlockSize;
		if (RemainingSize != 0) {
			Status = NtWriteFile(hFile, 0, NULL, NULL, &IoStatus, ptr, RemainingSize, pPosition, NULL);
			if (!NT_SUCCESS(Status))
				__leave;
			BytesWritten += IoStatus.Information;
		}

	}
	__finally {
		if (hFile != NULL) {
			if (Flush == TRUE) NtFlushBuffersFile(hFile, &IoStatus);
			NtClose(hFile);
		}
		RtlFreeUnicodeString(&NtFileName);
	}
	return BytesWritten;
}

