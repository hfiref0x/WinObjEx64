/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.30
*
*  DATE:        27 Oct 2015
*
*  Program entry point and main window handler.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#define OEMRESOURCE
#include  <process.h>
#include "global.h"
#include "aboutDlg.h"
#include "findDlg.h"
#include "propDlg.h"
#include "extras.h"

#pragma comment(lib, "comctl32.lib")

#if (_MSC_VER >= 1900) 
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(linker,"/MERGE:.rdata=.text")
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif

static LONG	SplitterPos = 180;
static LONG	SortColumn = 0;
HTREEITEM	SelectedTreeItem = NULL;

/*
* MainWindowObjectListCompareFunc
*
* Purpose:
*
* Main window listview comparer function.
*
*/
INT CALLBACK MainWindowObjectListCompareFunc(
	_In_ LPARAM lParam1,
	_In_ LPARAM lParam2,
	_In_ LPARAM lParamSort
	)
{
	LPWSTR lpItem1, lpItem2;
	INT nResult = 0;
	
	lpItem1 = supGetItemText(ObjectList, (INT)lParam1, (INT)lParamSort, NULL);
	lpItem2 = supGetItemText(ObjectList, (INT)lParam2, (INT)lParamSort, NULL);

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

/*
* MainWindowHandleObjectTreeProp
*
* Purpose:
*
* Object Tree properties per selected item.
*
*/
VOID MainWindowHandleObjectTreeProp(
	_In_ HWND hwnd
	)
{
	TV_ITEM		tvi;
	WCHAR		szBuffer[MAX_PATH + 1];

	if (g_PropWindow != NULL)
		return;

	if (SelectedTreeItem == NULL)
		return;

	szBuffer[0] = 0; //mars workaround

	RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
	RtlSecureZeroMemory(&tvi, sizeof(TV_ITEM));

	tvi.pszText = szBuffer;
	tvi.cchTextMax = MAX_PATH;
	tvi.mask = TVIF_TEXT;
	tvi.hItem = SelectedTreeItem;
	if (TreeView_GetItem(ObjectTree, &tvi)) {
		propCreateDialog(hwnd, szBuffer, T_ObjectNames[TYPE_DIRECTORY], NULL);
	}
}

/*
* MainWindowHandleObjectListProp
*
* Purpose:
*
* Object List properties per selected item.
*
*/
VOID MainWindowHandleObjectListProp(
	_In_ HWND hwnd
	)
{
	INT nSelected;
	LPWSTR	lpItemText, lpType, lpDesc = NULL;

	if (g_PropWindow != NULL)
		return;

	//nothing selected, go away
	if (ListView_GetSelectedCount(ObjectList) == 0) {
		return;
	}

	nSelected = ListView_GetSelectionMark(ObjectList);
	if (nSelected == -1) {
		return;
	}

	lpItemText = supGetItemText(ObjectList, nSelected, 0, NULL);
	if (lpItemText) {
		lpType = supGetItemText(ObjectList, nSelected, 1, NULL);
		if (lpType) {

			//lpDesc is not important, we can work if it NULL
			lpDesc = supGetItemText(ObjectList, nSelected, 2, NULL);
			
			propCreateDialog(hwnd, lpItemText, lpType, lpDesc);

			if (lpDesc) {
				HeapFree(GetProcessHeap(), 0, lpDesc);
			}
			HeapFree(GetProcessHeap(), 0, lpType);
		}
		HeapFree(GetProcessHeap(), 0, lpItemText);
	}
}

/*
* MainWindowOnRefresh
*
* Purpose:
*
* Main Window Refresh handler.
*
*/
VOID MainWindowOnRefresh(
	_In_ HWND hwnd
	)
{
	LPWSTR	CurrentObject;
	SIZE_T	len;

	UNREFERENCED_PARAMETER(hwnd);

	supSetWaitCursor(TRUE);

	if (g_kdctx.hDevice != NULL) {
		ObListDestroy(&g_kdctx.ObjectList);
		if (g_kdctx.hThreadWorker) {
			WaitForSingleObject(g_kdctx.hThreadWorker, INFINITE);
			CloseHandle(g_kdctx.hThreadWorker);
			g_kdctx.hThreadWorker = NULL;
		}

		//query object list info
		g_kdctx.hThreadWorker = CreateThread(NULL, 0,
			kdQueryProc,
			&g_kdctx, 0, NULL);
	}

	supFreeSCMSnapshot(g_enumParams.scmSnapshot);
	sapiFreeSnapshot(g_enumParams.sapiDB);
	RtlSecureZeroMemory(&g_enumParams, sizeof(g_enumParams));
	g_enumParams.scmSnapshot = supCreateSCMSnapshot(&g_enumParams.scmNumberOfEntries);
	g_enumParams.sapiDB = sapiCreateSetupDBSnapshot();
	g_enumParams.lpSubDirName = CurrentObjectPath;

	len = _strlen(CurrentObjectPath);
	CurrentObject = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (len + 1)*sizeof(WCHAR));
	if (CurrentObject)
		_strcpy(CurrentObject, CurrentObjectPath);

	TreeView_DeleteAllItems(ObjectTree);
	ListObjectDirectoryTree(L"\\", NULL, NULL);
	TreeView_SelectItem(ObjectTree, TreeView_GetRoot(ObjectTree));

	if (CurrentObject) {
		ListToObject(CurrentObject);
		HeapFree(GetProcessHeap(), 0, CurrentObject);
	}

	supSetWaitCursor(FALSE);
}

/*
* MainWindowHandleWMCommand
*
* Purpose:
*
* Main window WM_COMMAND handler.
*
*/
LRESULT MainWindowHandleWMCommand(
	_In_ HWND hwnd,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
	)
{
	LPWSTR		lpItemText;
	HWND		hwndFocus;


	UNREFERENCED_PARAMETER(lParam);

	switch (LOWORD(wParam)) {

	case ID_FILE_RUNASADMIN:
		supRunAsAdmin();
		break;

	case ID_FILE_EXIT:
		PostQuitMessage(0);
		break;

	case ID_OBJECT_PROPERTIES:
		hwndFocus = GetFocus();
		if (hwndFocus == ObjectList) {
			MainWindowHandleObjectListProp(hwnd);
		}
		if (hwndFocus == ObjectTree) {
			MainWindowHandleObjectTreeProp(hwnd);
		}
		break;

	case ID_OBJECT_GOTOLINKTARGET:
		lpItemText = supGetItemText(ObjectList, ListView_GetSelectionMark(ObjectList), 2, NULL);
		if (lpItemText) {
			if (_strcmpi(lpItemText, L"\\??") == 0) {
				ListToObject(L"\\GLOBAL??");
			}
			else {
				ListToObject(lpItemText);
			}
			HeapFree(GetProcessHeap(), 0, lpItemText);
		}
		else {
			lpItemText = supGetItemText(ObjectList, ListView_GetSelectionMark(ObjectList), 0, NULL);
			if (lpItemText) {
				if (
					(_strcmpi(lpItemText, L"GLOBALROOT") == 0) && 
					(_strcmpi(CurrentObjectPath, L"\\GLOBAL??") == 0)
					) 
				{
					ListToObject(L"\\");
				}
				HeapFree(GetProcessHeap(), 0, lpItemText);
			}
		}
		break;

	case ID_FIND_FINDOBJECT:
		FindDlgCreate(hwnd);
		break;

	case ID_VIEW_REFRESH:
		MainWindowOnRefresh(hwnd);
		break;

	case ID_EXTRAS_PIPES:
		extrasShowPipeDialog(hwnd);
		break;

	case ID_EXTRAS_USERSHAREDDATA:
		extrasShowUserSharedDataDialog(hwnd);
		break;

	case ID_EXTRAS_PRIVATENAMESPACES:
		if (g_kdctx.osver.dwBuildNumber <= 10240) {
			extrasShowPrivateNamespacesDialog(hwnd);
		}
		break;

	case ID_HELP_ABOUT:
		DialogBoxParam(g_hInstance, MAKEINTRESOURCE(IDD_DIALOG_ABOUT), 
			hwnd, (DLGPROC)&AboutDialogProc, 0);
		break;

	case ID_HELP_HELP:
		supShowHelp();
		break;

	default:
		break;
	}
	return FALSE;
}

/*
* MainWindowTreeViewSelChanged
*
* Purpose:
*
* Tree List TVN_ITEMEXPANDED, TVN_SELCHANGED handler.
*
*/
VOID MainWindowTreeViewSelChanged(
	_In_ LPNMTREEVIEWW trhdr
	)
{
	WCHAR			text[MAX_PATH + 2];
	HTREEITEM		hitem, root;
	TVITEMEXW		sitem;
	POE_LIST_ITEM	list = NULL, prevlist = NULL;
	SIZE_T			p = 1; // size of empty string buffer in characters

	if (trhdr == NULL)
		return;

	if (!trhdr->itemNew.hItem)
		return;

	if (CurrentObjectPath != NULL)
		HeapFree(GetProcessHeap(), 0, CurrentObjectPath);

	root = TreeView_GetRoot(trhdr->hdr.hwndFrom);

	// build the path from bottom to top and counting string buffer size
	for (hitem = trhdr->itemNew.hItem; hitem != root; 
		hitem = TreeView_GetParent(trhdr->hdr.hwndFrom, hitem)) 
	{
		RtlSecureZeroMemory(&sitem, sizeof(sitem));
		RtlSecureZeroMemory(&text, sizeof(text));
		sitem.mask = TVIF_HANDLE | TVIF_TEXT;
		sitem.hItem = hitem;
		sitem.pszText = text;
		sitem.cchTextMax = MAX_PATH;
		TreeView_GetItem(trhdr->hdr.hwndFrom, &sitem);

		p += _strlen(text) + 1; //+1 for '\'

		list = HeapAlloc(GetProcessHeap(), 0, sizeof(OE_LIST_ITEM));
		if (list) {
			list->Prev = prevlist;
			list->TreeItem = hitem;
		}
		prevlist = list;
	}

	if (list == NULL) {
		CurrentObjectPath = HeapAlloc(GetProcessHeap(), 0, 2 * sizeof(WCHAR));
		if (CurrentObjectPath) {
			CurrentObjectPath[0] = L'\\';
			CurrentObjectPath[1] = 0;
		}
		return;
	}

	list = prevlist;
	CurrentObjectPath = HeapAlloc(GetProcessHeap(), 0, p*sizeof(WCHAR));
	if (CurrentObjectPath) {
		p = 0;
		// building the final string
		while (list != NULL) {
			RtlSecureZeroMemory(&sitem, sizeof(sitem));
			RtlSecureZeroMemory(&text, sizeof(text));
			sitem.mask = TVIF_HANDLE | TVIF_TEXT;
			sitem.hItem = list->TreeItem;
			sitem.pszText = text;
			sitem.cchTextMax = MAX_PATH;
			TreeView_GetItem(trhdr->hdr.hwndFrom, &sitem);

			CurrentObjectPath[p] = L'\\';
			p++;
			_strcpy(CurrentObjectPath + p, text);
			p += _strlen(text);

			prevlist = list->Prev;
			HeapFree(GetProcessHeap(), 0, list);
			list = prevlist;
		}
	}
	return;
}

/*
* MainWindowHandleWMNotify
*
* Purpose:
*
* Main window WM_NOTIFY handler.
*
*/
LRESULT MainWindowHandleWMNotify(
	_In_ HWND hwnd,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
	)
{
	INT				c, k;
	LPNMHDR			hdr = (LPNMHDR)lParam;
	LPTOOLTIPTEXT	lpttt;
	LPNMLISTVIEW	lvn;
	LPNMTREEVIEW	lpnmTreeView;
	LPWSTR			str;
	SIZE_T			lcp;
	LVITEMW			lvitem;
	LVCOLUMNW		col;
	TVHITTESTINFO	hti;
	POINT			pt;
	WCHAR			item_string[MAX_PATH + 1];

	UNREFERENCED_PARAMETER(wParam);

	if (hdr) {

		if (hdr->hwndFrom == ObjectTree) {
			switch (hdr->code) {
			case TVN_ITEMEXPANDED:
			case TVN_SELCHANGED:
				SetFocus(ObjectTree);
				supSetWaitCursor(TRUE);
				MainWindowTreeViewSelChanged((LPNMTREEVIEWW)lParam);
				SendMessageW(StatusBar, WM_SETTEXT, 0, (LPARAM)CurrentObjectPath);

				g_enumParams.lpSubDirName = CurrentObjectPath;
				ListObjectsInDirectory(&g_enumParams);

				ListView_SortItemsEx(ObjectList, &MainWindowObjectListCompareFunc, SortColumn);

				supSetWaitCursor(FALSE);

				lpnmTreeView = (LPNMTREEVIEW)lParam;
				if (lpnmTreeView) {
					SelectedTreeItem = lpnmTreeView->itemNew.hItem;
				}
				break;

			case NM_RCLICK:
				GetCursorPos(&pt);
				hti.pt = pt;
				ScreenToClient(hdr->hwndFrom, &hti.pt);
				if (TreeView_HitTest(hdr->hwndFrom, &hti) &&
					(hti.flags & (TVHT_ONITEM | TVHT_ONITEMRIGHT))) {
					SelectedTreeItem = hti.hItem;
					if (hdr->code == NM_RCLICK) {
						TreeView_SelectItem(ObjectTree, SelectedTreeItem);
						SendMessageW(StatusBar, WM_SETTEXT, 0, (LPARAM)CurrentObjectPath);
						supHandleTreePopupMenu(hwnd, &pt);
					}
				}
				break;
			}
		}

		if (hdr->hwndFrom == ObjectList) {
			switch (hdr->code) {
			case NM_SETFOCUS:
				if (ListView_GetSelectionMark(ObjectList) == -1) {
					lvitem.mask = LVIF_STATE;
					lvitem.iItem = 0;
					lvitem.state = LVIS_SELECTED | LVIS_FOCUSED;
					lvitem.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
					ListView_SetItem(ObjectList, &lvitem);
				}

				break;
			case LVN_ITEMCHANGED:
				lvn = (LPNMLISTVIEW)lParam;
				RtlSecureZeroMemory(&item_string, sizeof(item_string));
				ListView_GetItemText(ObjectList, lvn->iItem, 0, item_string, MAX_PATH);
				lcp = _strlen(CurrentObjectPath);
				str = HeapAlloc(GetProcessHeap(), 0, (lcp + _strlen(item_string) + 4) * sizeof(WCHAR));
				if (str == NULL)
					break;
				_strcpy(str, CurrentObjectPath);

				if ((str[0] == '\\') && (str[1] == 0)) {
					_strcpy(str + lcp, item_string);
				}
				else {
					str[lcp] = '\\';
					_strcpy(str + lcp + 1, item_string);
				}
				SendMessageW(StatusBar, WM_SETTEXT, 0, (LPARAM)str);
				HeapFree(GetProcessHeap(), 0, str);
				break;

				//handle sort by column
			case LVN_COLUMNCLICK:
				bSortInverse = !bSortInverse;
				SortColumn = ((NMLISTVIEW *)lParam)->iSubItem;
				ListView_SortItemsEx(ObjectList, &MainWindowObjectListCompareFunc, SortColumn);

				RtlSecureZeroMemory(&col, sizeof(col));
				col.mask = LVCF_IMAGE;
				col.iImage = -1;

				for (c = 0; c < 3; c++)
					ListView_SetColumn(ObjectList, c, &col);

				k = ImageList_GetImageCount(ListViewImages);
				if (bSortInverse)
					col.iImage = k - 2;
				else
					col.iImage = k - 1;

				ListView_SetColumn(ObjectList, ((NMLISTVIEW *)lParam)->iSubItem, &col);

				break;
			case NM_CLICK:
				c = ((LPNMITEMACTIVATE)lParam)->iItem;
				EnableMenuItem(GetSubMenu(GetMenu(hwnd), 2), ID_OBJECT_GOTOLINKTARGET,
					(supIsSymlink(c)) ? MF_BYCOMMAND : MF_BYCOMMAND | MF_GRAYED);
				break;

			case NM_DBLCLK:
				MainWindowHandleObjectListProp(hwnd);
				break;

			default:
				break;
			}
		}

		//handle tooltip
		if (hdr->code == TTN_GETDISPINFO) {
			lpttt = (LPTOOLTIPTEXT)lParam;

			switch (lpttt->hdr.idFrom) {

			case ID_OBJECT_PROPERTIES:
			case ID_VIEW_REFRESH:
			case ID_FIND_FINDOBJECT:
				lpttt->hinst = g_hInstance;
				lpttt->lpszText = MAKEINTRESOURCE(lpttt->hdr.idFrom);
				lpttt->uFlags |= TTF_DI_SETITEM;
				break;

			default:
				break;

			}
		}
	}
	return FALSE;
}

/*
* MainWindowResizeHandler
*
* Purpose:
*
* Main window WM_SIZE handler.
*
*/
VOID MainWindowResizeHandler(
	_In_ LONG sPos
	)
{
	RECT ToolBarRect, StatusBarRect;
	LONG posY, sizeY, sizeX;

	if (ToolBar1 != NULL) {
		SendMessage(ToolBar1, WM_SIZE, 0, 0);
		SendMessage(StatusBar, WM_SIZE, 0, 0);
		RtlSecureZeroMemory(&ToolBarRect, sizeof(ToolBarRect));
		RtlSecureZeroMemory(&StatusBarRect, sizeof(StatusBarRect));
		GetWindowRect(ToolBar1, &ToolBarRect);
		GetWindowRect(StatusBar, &StatusBarRect);

		sizeX = ToolBarRect.right - ToolBarRect.left;
		if (sPos > sizeX - SplitterMargin)
			sPos = sizeX - SplitterMargin - 1;

		sizeY = StatusBarRect.top - ToolBarRect.bottom;
		posY = ToolBarRect.bottom - ToolBarRect.top;
		sizeX = ToolBarRect.right - ToolBarRect.left - sPos - SplitterSize;

		SetWindowPos(ObjectTree, NULL, 0, posY, sPos, sizeY, 0);
		SetWindowPos(ObjectList, NULL, sPos + SplitterSize, posY, sizeX, sizeY, 0);
		SetWindowPos(Splitter, NULL, sPos, posY, SplitterSize, sizeY, 0);
	}
}

/*
* MainWindowProc
*
* Purpose:
*
* Main window procedure.
*
*/
LRESULT CALLBACK MainWindowProc(
	_In_ HWND hwnd,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
	)
{
	INT					mark;
	RECT				ToolBarRect, crc;
	LPMEASUREITEMSTRUCT pms;
	LPDRAWITEMSTRUCT	pds;

	switch (uMsg) {
	case WM_CONTEXTMENU:

		RtlSecureZeroMemory(&crc, sizeof(crc));

		if ((HWND)wParam == ObjectTree) {
			TreeView_GetItemRect(ObjectTree, TreeView_GetSelection(ObjectTree), &crc, TRUE);
			crc.top = crc.bottom;
			ClientToScreen(ObjectTree, (LPPOINT)&crc);
			supHandleTreePopupMenu(hwnd, (LPPOINT)&crc);
		}

		if ((HWND)wParam == ObjectList) {
			mark = ListView_GetSelectionMark(ObjectList);

			if ((DWORD)lParam == MAKELPARAM(-1, -1)) {	
				ListView_GetItemRect(ObjectList, mark, &crc, TRUE);
				crc.top = crc.bottom;
				ClientToScreen(ObjectList, (LPPOINT)&crc);
			}
			else
				GetCursorPos((LPPOINT)&crc);

			supHandleObjectPopupMenu(hwnd, mark, (LPPOINT)&crc);
		}
		break;

	case WM_COMMAND:
		MainWindowHandleWMCommand(hwnd, wParam, lParam);
		break;

	case WM_NOTIFY:
		MainWindowHandleWMNotify(hwnd, wParam, lParam);
		break;

	case WM_MEASUREITEM:
		pms = (LPMEASUREITEMSTRUCT)lParam;
		if (pms && pms->CtlType == ODT_MENU) {
			pms->itemWidth = 16;
			pms->itemHeight = 16;
		}
		break;

	case WM_DRAWITEM:
		pds = (LPDRAWITEMSTRUCT)lParam;
		if (pds && pds->CtlType == ODT_MENU) {
			DrawIconEx(pds->hDC, pds->rcItem.left - 15,
				pds->rcItem.top,
				(HICON)pds->itemData,
				16, 16, 0, NULL, DI_NORMAL);
		}
		break;

	case WM_CLOSE:
		PostQuitMessage(0);
		break;

	case WM_LBUTTONDOWN:
		SetCapture(MainWindow);
		break;

	case WM_LBUTTONUP:
		ReleaseCapture();
		break;

	case WM_MOUSEMOVE:
		if ((wParam & MK_LBUTTON) != 0) {
			GetClientRect(MainWindow, &ToolBarRect);
			SplitterPos = (SHORT)LOWORD(lParam);
			if (SplitterPos < SplitterMargin)
				SplitterPos = SplitterMargin;
			if (SplitterPos > ToolBarRect.right - SplitterMargin)
				SplitterPos = ToolBarRect.right - SplitterMargin;
			SendMessage(MainWindow, WM_SIZE, 0, 0);
			UpdateWindow(MainWindow);
		}
		break;

	case WM_SIZE:
		if (!IsIconic(hwnd)) {
			MainWindowResizeHandler(SplitterPos);
		}
		break;

	case WM_GETMINMAXINFO:
		if (lParam) {
			((PMINMAXINFO)lParam)->ptMinTrackSize.x = 400;
			((PMINMAXINFO)lParam)->ptMinTrackSize.y = 256;
		}
		break;
	}
	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

#ifdef _DEBUG

HANDLE hObject = NULL;

VOID TestIoCompletion()
{
	OBJECT_ATTRIBUTES obja;
	UNICODE_STRING ustr;
	RtlInitUnicodeString(&ustr, L"\\BaseNamedObjects\\TestCompletion");
	InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
	NtCreateIoCompletion(&hObject, IO_COMPLETION_ALL_ACCESS, &obja, 100);
}


VOID TestTimer()
{
	HANDLE hTimer = NULL;
	LARGE_INTEGER liDueTime;

	liDueTime.QuadPart = -1000000000000LL;

	hTimer = CreateWaitableTimer(NULL, TRUE, L"TestTimer");
	SetWaitableTimer(hTimer, &liDueTime, 0, NULL, NULL, 0);
}

VOID TestTransaction()
{
	
	OBJECT_ATTRIBUTES obja;
	UNICODE_STRING ustr;
	//TmTx
	RtlInitUnicodeString(&ustr, L"\\BaseNamedObjects\\TestTransaction");
	InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
	NtCreateTransaction(&hObject, TRANSACTION_ALL_ACCESS, &obja, NULL, NULL, 0, 0, 0, NULL, NULL);
}

#include <Sddl.h>

HANDLE g_hNamespace = NULL, g_hMutex = NULL;

VOID TestPrivateNamespace()
{
	HANDLE hBoundaryDescriptor = NULL;
	BOOL cond = FALSE;
	SECURITY_ATTRIBUTES sa;

	BYTE localAdminSID[SECURITY_MAX_SID_SIZE];
	PSID pLocalAdminSID = &localAdminSID; 
	DWORD cbSID = sizeof(localAdminSID);
	CHAR text[1000];

	do {
		RtlSecureZeroMemory(&localAdminSID, sizeof(localAdminSID));
		hBoundaryDescriptor = CreateBoundaryDescriptor(TEXT("TestBoundaryDescriptor"), 0);
		if (hBoundaryDescriptor == NULL) {
			break;
		}

		if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, pLocalAdminSID, &cbSID)) {
			break;
		}
		if (!AddSIDToBoundaryDescriptor(&hBoundaryDescriptor, pLocalAdminSID)) {
			break;
		}

		RtlSecureZeroMemory(&sa, sizeof(sa));
		sa.nLength = sizeof(sa); 
		sa.bInheritHandle = FALSE;
		if (!ConvertStringSecurityDescriptorToSecurityDescriptor(TEXT("D:(A;;GA;;;BA)"),
			SDDL_REVISION_1, &sa.lpSecurityDescriptor, NULL)) {
			break;
		}

		g_hNamespace = CreatePrivateNamespace(&sa, hBoundaryDescriptor, TEXT("Mynamespace2"));
		LocalFree(sa.lpSecurityDescriptor);
		
		if (g_hNamespace == NULL) {
			ultostr_a(GetLastError(), text);
			OutputDebugStringA(text);
			break;
		}

		g_hMutex = CreateMutex(NULL, FALSE, TEXT("Mynamespace2\\TestMutex"));

	} while (cond);

}

#endif

/*
* MainDlgMsgHandler
*
* Purpose:
*
* Check window message against existing dialogs.
*
*/
BOOL MainDlgMsgHandler(
	MSG msg
	)
{
	UINT c;

	for (c = 0; c < WOBJ_MAX_DIALOGS; c++) {
		if ((g_wobjDialogs[c] != NULL)) {
			if (IsDialogMessage(g_wobjDialogs[c], &msg))
				return TRUE;
		}
	}

	if (g_SubPropWindow != NULL)
		if (IsDialogMessage(g_SubPropWindow, &msg))
			return TRUE;

	if (g_PropWindow != NULL)
		if (IsDialogMessage(g_PropWindow, &msg))
			return TRUE;

	return FALSE;
}

/*
* WinObjExMain
*
* Purpose:
*
* Actual program entry point.
*
*/
void WinObjExMain()
{
	MSG						msg1;
	WNDCLASSEX				wincls;
	BOOL					IsFullAdmin = FALSE, rv = TRUE, cond = FALSE;
	ATOM					class_atom = 0;
	INITCOMMONCONTROLSEX	icc;
	LVCOLUMNW				col;
	SHSTOCKICONINFO			sii;
	HMENU					hMenu;
	HACCEL					hAccTable = 0;
	WCHAR					szWindowTitle[100];
	HANDLE					tmpb;


#ifdef _DEBUG
	TestPrivateNamespace();
	//TestIoCompletion();
	//TestTimer();
	//TestTransaction();
#endif

	pHtmlHelpW = NULL;
	CurrentObjectPath = NULL;
	bSortInverse = FALSE;
	g_hInstance = GetModuleHandle(NULL);
	RtlSecureZeroMemory(szWindowTitle, sizeof(szWindowTitle));

	//clear dialogs array
	RtlSecureZeroMemory(g_wobjDialogs, sizeof(g_wobjDialogs));

	// do not move anywhere
	IsFullAdmin = supUserIsFullAdmin();
	supInit(IsFullAdmin);

	//create main window and it components
	wincls.cbSize = sizeof(WNDCLASSEX);
	wincls.style = 0;
	wincls.lpfnWndProc = &MainWindowProc;
	wincls.cbClsExtra = 0;
	wincls.cbWndExtra = 0;
	wincls.hInstance = g_hInstance;
	wincls.hIcon = (HICON)LoadImage(g_hInstance, MAKEINTRESOURCE(IDI_ICON_MAIN), IMAGE_ICON, 0, 0, LR_SHARED);
	wincls.hCursor = (HCURSOR)LoadImage(NULL, MAKEINTRESOURCE(OCR_SIZEWE), IMAGE_CURSOR, 0, 0, LR_SHARED);
	wincls.hbrBackground = NULL;
	wincls.lpszMenuName = MAKEINTRESOURCE(IDR_MENU1);
	wincls.lpszClassName = MAINWINDOWCLASSNAME;
	wincls.hIconSm = 0;

	do {
		class_atom = RegisterClassEx(&wincls);
		if (class_atom == 0)
			break;

		_strcpy(szWindowTitle, PROGRAM_NAME);
		if (IsFullAdmin != FALSE) {
			_strcat(szWindowTitle, L" (Administrator)");
		}

		MainWindow = CreateWindowEx(0, MAKEINTATOM(class_atom), szWindowTitle,
			WS_VISIBLE | WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 800, 600, NULL, NULL, g_hInstance, NULL);
		if (MainWindow == NULL)
			break;

		icc.dwSize = sizeof(icc);
		icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES | ICC_BAR_CLASSES | ICC_TAB_CLASSES;
		if (!InitCommonControlsEx(&icc))
			break;

		StatusBar = CreateWindowEx(0, STATUSCLASSNAME, NULL,
			WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, MainWindow, (HMENU)1001, g_hInstance, NULL);

		ObjectTree = CreateWindowEx(WS_EX_CLIENTEDGE, WC_TREEVIEW, NULL,
			WS_VISIBLE | WS_CHILD | WS_TABSTOP | TVS_DISABLEDRAGDROP | TVS_HASBUTTONS | 
			TVS_HASLINES | TVS_LINESATROOT, 0, 0, 0, 0, MainWindow, (HMENU)1002, g_hInstance, NULL);

		if (ObjectTree == NULL)
			break;

		ObjectList = CreateWindowEx(WS_EX_CLIENTEDGE, WC_LISTVIEW, NULL,
			WS_VISIBLE | WS_CHILD | WS_TABSTOP | LVS_AUTOARRANGE | LVS_REPORT | 
			LVS_SHOWSELALWAYS | LVS_SINGLESEL | LVS_SHAREIMAGELISTS, 0, 0, 0, 0, 
			MainWindow, (HMENU)1003, g_hInstance, NULL);

		if (ObjectList == NULL)
			break;

		ToolBar1 = CreateWindowEx(0, TOOLBARCLASSNAME, NULL,
			WS_VISIBLE | WS_CHILD | CCS_TOP | TBSTYLE_FLAT | TBSTYLE_TRANSPARENT | 
			TBSTYLE_TOOLTIPS, 0, 0, 0, 0, MainWindow, (HMENU)1004, g_hInstance, NULL);

		if (ToolBar1 == NULL)
			break;

		Splitter = CreateWindowEx(0, WC_STATIC, NULL,
			WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, MainWindow, (HMENU)1005, g_hInstance, NULL);

		// initialization of views
		SendMessage(MainWindow, WM_SIZE, 0, 0);
		ListView_SetExtendedListViewStyle(ObjectList, 
			LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_LABELTIP | LVS_EX_DOUBLEBUFFER);

		// set tree imagelist
		TreeViewImages = supLoadImageList(g_hInstance, IDI_ICON_VIEW_DEFAULT, IDI_ICON_VIEW_SELECTED);
		if (TreeViewImages) {
			TreeView_SetImageList(ObjectTree, TreeViewImages, TVSIL_NORMAL);
		}

		//insert run as admin menu entry
		if (IsFullAdmin == FALSE) {
			hMenu = GetSubMenu(GetMenu(MainWindow), 0);
			InsertMenu(hMenu, 0, MF_BYPOSITION, ID_FILE_RUNASADMIN, T_RUNASADMIN);
			InsertMenu(hMenu, 1, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
			//set menu shield icon
			RtlSecureZeroMemory(&sii, sizeof(sii));
			sii.cbSize = sizeof(sii);
			if (SHGetStockIconInfo(SIID_SHIELD, SHGSI_ICON | SHGFI_SMALLICON, &sii) == S_OK) {
				supSetMenuIcon(hMenu, ID_FILE_RUNASADMIN, (ULONG_PTR)sii.hIcon);
			}
		}

		//unsupported
		if (g_kdctx.osver.dwBuildNumber > 10240) {
			DeleteMenu(GetSubMenu(GetMenu(MainWindow), 4), ID_EXTRAS_PRIVATENAMESPACES, MF_BYCOMMAND);
		}

		//load listview images
		ListViewImages = supLoadImageList(g_hInstance, IDI_ICON_DEVICE, IDI_ICON_UNKNOWN);
		if (ListViewImages) {
			tmpb = LoadImage(g_hInstance, MAKEINTRESOURCE(IDI_ICON_SORTUP), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
			if (tmpb) {
				ImageList_ReplaceIcon(ListViewImages, -1, tmpb);
				DestroyIcon(tmpb);
			}
			tmpb = LoadImage(g_hInstance, MAKEINTRESOURCE(IDI_ICON_SORTDOWN), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
			if (tmpb) {
				ImageList_ReplaceIcon(ListViewImages, -1, tmpb);
				DestroyIcon(tmpb);
			}
			ListView_SetImageList(ObjectList, ListViewImages, LVSIL_SMALL);
		}

		//load toolbar images
		ToolBarMenuImages = ImageList_LoadImage(g_hInstance, MAKEINTRESOURCE(IDB_BITMAP1), 
			16, 7, CLR_DEFAULT, IMAGE_BITMAP, LR_CREATEDIBSECTION);

		if (ToolBarMenuImages) {

			supCreateToolbarButtons(ToolBar1);

			//set menu icons
			hMenu = GetSubMenu(GetMenu(MainWindow), 1);
			if (hMenu) {
				supSetMenuIcon(hMenu, ID_VIEW_REFRESH,
					(ULONG_PTR)ImageList_ExtractIcon(g_hInstance, ToolBarMenuImages, 1));
			}
			hMenu = GetSubMenu(GetMenu(MainWindow), 2);
			if (hMenu && ListViewImages) {
				supSetMenuIcon(hMenu, ID_OBJECT_PROPERTIES,
					(ULONG_PTR)ImageList_ExtractIcon(g_hInstance, ToolBarMenuImages, 0));
				supSetMenuIcon(hMenu, ID_OBJECT_GOTOLINKTARGET,
					(ULONG_PTR)ImageList_ExtractIcon(g_hInstance, ListViewImages, 
					ID_FROM_VALUE(IDI_ICON_SYMLINK)));
			}

			//set object -> find object menu image
			hMenu = GetSubMenu(GetMenu(MainWindow), 3);
			if (hMenu) {
				supSetMenuIcon(hMenu, ID_FIND_FINDOBJECT,
					(ULONG_PTR)ImageList_ExtractIcon(g_hInstance, ToolBarMenuImages, 2));
			}

			//set extras-pipe menu image
			hMenu = GetSubMenu(GetMenu(MainWindow), 4);
			if (hMenu) {
				supSetMenuIcon(hMenu, ID_EXTRAS_PIPES,
					(ULONG_PTR)ImageList_ExtractIcon(g_hInstance, ToolBarMenuImages, 6));
			}

			//set help menu image
			hMenu = GetSubMenu(GetMenu(MainWindow), 5);
			if (hMenu) {
				supSetMenuIcon(hMenu, ID_HELP_HELP,
					(ULONG_PTR)ImageList_ExtractIcon(g_hInstance, ToolBarMenuImages, 3));
			}

		}

		hAccTable = LoadAccelerators(g_hInstance, MAKEINTRESOURCE(IDR_ACCELERATOR1));

		//create ObjectList columns
		RtlSecureZeroMemory(&col, sizeof(col));
		col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER | LVCF_IMAGE;
		col.iSubItem = 1;
		col.pszText = L"Name";
		col.fmt = LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT;
		col.iOrder = 0;
		col.iImage = -1;
		if (ListViewImages) {
			col.iImage = ImageList_GetImageCount(ListViewImages) - 1;
		}
		col.cx = 300;
		ListView_InsertColumn(ObjectList, 1, &col);

		col.iSubItem = 2;
		col.pszText = L"Type";
		col.iOrder = 1;
		col.iImage = -1;
		col.cx = 100;
		ListView_InsertColumn(ObjectList, 2, &col);

		col.iSubItem = 3;
		col.pszText = L"Additional Information";
		col.iOrder = 2;
		col.iImage = -1;
		col.cx = 170;
		ListView_InsertColumn(ObjectList, 3, &col);

		ListObjectDirectoryTree(L"\\", NULL, NULL);

		TreeView_SelectItem(ObjectTree, TreeView_GetRoot(ObjectTree));
		SetFocus(ObjectTree);

		do {
			rv = GetMessage(&msg1, NULL, 0, 0);

			if (rv == -1)
				break;

			if (MainDlgMsgHandler(msg1)) 
				continue;

			if (IsDialogMessage(MainWindow, &msg1)) {
				TranslateAccelerator(MainWindow, hAccTable, &msg1);
				continue;
			}

			TranslateMessage(&msg1);
			DispatchMessage(&msg1);
		} while (rv != 0);

	} while (cond);

	if (class_atom != 0)
		UnregisterClass(MAKEINTATOM(class_atom), g_hInstance);

	//do not move anywhere
	
	supShutdown();

#ifdef _DEBUG
	if (hObject) NtClose(hObject);

	if (g_hMutex != NULL) {
		CloseHandle(g_hMutex);
	}
	if (g_hNamespace != NULL) {
		ClosePrivateNamespace(g_hNamespace, PRIVATE_NAMESPACE_FLAG_DESTROY);
	}

#endif
}

/*
* main
*
* Purpose:
*
* Program entry point.
*
*/
void main()
{

	__security_init_cookie();

	WinObjExMain();
	ExitProcess(0);
}
