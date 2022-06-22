/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2022
*
*  TITLE:       PROPPROCESS.C
*
*  VERSION:     2.00
*
*  DATE:        19 Jun 2022
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "propDlg.h"
#include "extras.h"

#define COLUMN_PSLIST_NAME          0
#define COLUMN_PSLIST_ID            1
#define COLUMN_PSLIST_HANDLE        2
#define COLUMN_PSLIST_GRANTEDACCESS 3

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
    _In_ LPARAM lpContextParam
)
{
    INT       nResult = 0;
    LPWSTR    lpItem1 = NULL, lpItem2 = NULL, FirstToCompare, SecondToCompare;
    ULONG_PTR Value1, Value2;

    LPARAM lvColumnToSort;

    EXTRASCONTEXT* pDlgContext;

    pDlgContext = (EXTRASCONTEXT*)lpContextParam;
    if (pDlgContext == NULL)
        return 0;

    lvColumnToSort = (LPARAM)pDlgContext->lvColumnToSort;

    //
    // Sort Handle/GrantedAccess value column.
    //
    if ((lvColumnToSort == COLUMN_PSLIST_HANDLE) || 
        (lvColumnToSort == COLUMN_PSLIST_GRANTEDACCESS)) 
    {
        return supGetMaxOfTwoU64FromHex(
            pDlgContext->ListView,
            lParam1,
            lParam2,
            lvColumnToSort,
            pDlgContext->bInverseSort);
    }


    lpItem1 = supGetItemText(
        pDlgContext->ListView,
        (INT)lParam1,
        (INT)lvColumnToSort,
        NULL);

    if (lpItem1 == NULL) //can't be 0 for this dialog
        goto Done;

    lpItem2 = supGetItemText(
        pDlgContext->ListView,
        (INT)lParam2,
        (INT)lvColumnToSort,
        NULL);

    if (lpItem2 == NULL) //can't be 0 for this dialog
        goto Done;

    switch (lvColumnToSort) {
    case COLUMN_PSLIST_NAME:
        //
        // Name column.
        //
        if (pDlgContext->bInverseSort) {
            FirstToCompare = lpItem2;
            SecondToCompare = lpItem1;
        }
        else
        {
            FirstToCompare = lpItem1;
            SecondToCompare = lpItem2;
        }

        nResult = _strcmpi(FirstToCompare, SecondToCompare);
        break;

    case COLUMN_PSLIST_ID:
        //
        // Id column.
        //
        Value1 = strtou64(lpItem1);
        Value2 = strtou64(lpItem2);
        if (pDlgContext->bInverseSort)
            nResult = Value2 > Value1;
        else
            nResult = Value1 > Value2;
        break;

    }

Done:
    if (lpItem1) supHeapFree(lpItem1);
    if (lpItem2) supHeapFree(lpItem2);
    return nResult;
}

/*
* ProcessShowProperties
*
* Purpose:
*
* Query full target path and execute Windows shell properties dialog.
*
*/
VOID ProcessShowProperties(
    _In_ HWND hwndDlg,
    _In_ HWND hwndListView,
    _In_ INT iItem
)
{
    HANDLE          processId;
    PUNICODE_STRING pusFileName = NULL;

    WCHAR szBuffer[100];

    //
    // Query process id.
    //
    szBuffer[0] = 0;
    supGetItemText2(hwndListView, iItem, 1, szBuffer, RTL_NUMBER_OF(szBuffer));
    processId = UlongToHandle(_strtoul(szBuffer));

    //
    // Query process image filename and show shell properties dialog.
    //
    if (NT_SUCCESS(supQueryProcessImageFileNameWin32(processId, &pusFileName))) {

        if (pusFileName->Buffer && pusFileName->Length)
            supShowProperties(hwndDlg, pusFileName->Buffer);

        supHeapFree(pusFileName);
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
BOOL ProcessListHandleNotify(
    _In_ HWND hwndDlg,
    _In_ LPARAM lParam
)
{
    INT     nImageIndex;
    EXTRASCONTEXT* pDlgContext;
    NMLISTVIEW* pListView = (NMLISTVIEW*)lParam;
    HWND hwndListView;

    if (pListView == NULL)
        return FALSE;

    if (pListView->hdr.idFrom != ID_PROCESSLIST)
        return FALSE;

    hwndListView = pListView->hdr.hwndFrom;

    switch (pListView->hdr.code) {

    case LVN_COLUMNCLICK:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            pDlgContext->bInverseSort = (~pDlgContext->bInverseSort) & 1;
            pDlgContext->lvColumnToSort = pListView->iSubItem;

            ListView_SortItemsEx(
                hwndListView,
                &ProcessListCompareFunc,
                pDlgContext);

            if (pDlgContext->bInverseSort)
                nImageIndex = 1;
            else
                nImageIndex = 2;

            supUpdateLvColumnHeaderImage(
                hwndListView,
                pDlgContext->lvColumnCount,
                pDlgContext->lvColumnToSort,
                nImageIndex);
        }
        break;

    case NM_DBLCLK:

        ProcessShowProperties(
            hwndDlg,
            hwndListView,
            pListView->iItem);

        break;

    default:
        return FALSE;
    }

    return TRUE;
}

/*
* ProcessQueryInfo
*
* Purpose:
*
* Extracts icon resource from given process for use in listview and determines process WOW64 status.
*
*/
VOID ProcessQueryInfo(
    _In_ ULONG_PTR ProcessId,
    _Out_ HICON* pProcessIcon,
    _Out_ BOOL* pbIs32
)
{
    HANDLE          hProcess;
    NTSTATUS        ntStatus;

    HICON           hIcon = NULL;
    PUNICODE_STRING pusFileName = NULL;

    *pProcessIcon = NULL;
    *pbIs32 = FALSE;

    ntStatus = supOpenProcess((HANDLE)ProcessId,
        PROCESS_QUERY_LIMITED_INFORMATION,
        &hProcess);

    if (NT_SUCCESS(ntStatus)) {

        //
        // Query if this is wow64 process.
        //
        *pbIs32 = supIsProcess32bit(hProcess);

        //
        // Query process icon, first query win32 imagefilename then parse image resources.
        //
        ntStatus = supQueryProcessInformation(hProcess,
            ProcessImageFileNameWin32,
            &pusFileName,
            NULL);

        if (NT_SUCCESS(ntStatus)) {
            if (pusFileName->Buffer && pusFileName->Length) {
                hIcon = supGetMainIcon(pusFileName->Buffer, 16, 16);
                if (hIcon) {
                    *pProcessIcon = hIcon;
                }
            }
            supHeapFree(pusFileName);
        }

        NtClose(hProcess);
    }

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
    _In_ HWND hwndListView,
    _In_ HIMAGELIST ImageList,
    _In_ PVOID ProcessesList,
    _In_ PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX phti
)
{
    BOOL     bIsWow64;
    INT      nIndex, iImage;
    HICON    hIcon;
    LVITEM   lvitem;
    WCHAR    szBuffer[MAX_PATH * 2];

    if ((phti == NULL) || (ProcessesList == NULL)) {
        return;
    }

    //
    // Default image index.
    //
    iImage = 0;

    //
    // Set default process name as Unknown.
    //
    RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
    _strcpy(szBuffer, T_Unknown);

    if (supQueryProcessName(
        phti->UniqueProcessId,
        ProcessesList,
        szBuffer,
        MAX_PATH))
    {
        //
        // Id exists, extract icon
        // Skip idle, system
        //
        if (phti->UniqueProcessId > 4) {

            hIcon = NULL;
            bIsWow64 = FALSE;
            ProcessQueryInfo(phti->UniqueProcessId, &hIcon, &bIsWow64);

            if (hIcon) {
                iImage = ImageList_ReplaceIcon(ImageList, -1, hIcon);
                DestroyIcon(hIcon);
            }
            if (bIsWow64) {
                _strcat(szBuffer, L"*32");
            }
            
        }
    }

    RtlSecureZeroMemory(&lvitem, sizeof(lvitem));

    //
    // Process Name.
    //
    lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
    lvitem.iImage = iImage;
    lvitem.pszText = szBuffer;
    lvitem.iItem = MAXINT;
    nIndex = ListView_InsertItem(hwndListView, &lvitem);

    //
    // ProcessId.
    //
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    u64tostr(phti->UniqueProcessId, szBuffer);
    lvitem.mask = LVIF_TEXT;
    lvitem.iSubItem = 1;
    lvitem.iItem = nIndex;
    ListView_SetItem(hwndListView, &lvitem);

    //
    // Handle Value.
    //
    _strcpy(szBuffer, L"0x");
    u64tohex(phti->HandleValue, _strend(szBuffer));
    lvitem.iSubItem = 2;
    ListView_SetItem(hwndListView, &lvitem);

    //
    // Handle GrantedAccess.
    //
    _strcpy(szBuffer, L"0x");
    ultohex(phti->GrantedAccess, _strend(szBuffer));
    lvitem.iSubItem = 3;
    ListView_SetItem(hwndListView, &lvitem);
}

/*
* ProcessEnumHandlesCallback
*
* Purpose:
*
* Handles enumeration callback.
*
*/
BOOL ProcessEnumHandlesCallback(
    _In_ SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* HandleEntry,
    _In_ PVOID UserContext
)
{
    PPS_HANDLE_DUMP_ENUM_CONTEXT userCtx = (PPS_HANDLE_DUMP_ENUM_CONTEXT)UserContext;

    //
    // Is this what we want?
    //
    if (HandleEntry->ObjectTypeIndex == userCtx->ObjectTypeIndex) {
        if ((ULONG_PTR)HandleEntry->Object == userCtx->ObjectAddress) {

            //
            // Decode and add information to the list.
            //
            ProcessListAddItem(userCtx->ListView,
                userCtx->ImageList,
                userCtx->ProcessList,
                HandleEntry);
        }
    }

    return FALSE;
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
    _In_ HWND hwndDlg,
    _In_ PROP_OBJECT_INFO* Context,
    _In_ EXTRASCONTEXT* pDlgContext
)
{
    BOOL                            bObjectFound = FALSE;
    USHORT                          ObjectTypeIndex = 0;
    ULONG_PTR                       ObjectAddress = 0;
    ACCESS_MASK                     DesiredAccess;
    PVOID                           ProcessList = NULL;
    HANDLE                          hObject = NULL;
    HICON                           hIcon;
    PSYSTEM_HANDLE_INFORMATION_EX   pHandles = NULL;

    PS_HANDLE_DUMP_ENUM_CONTEXT     enumContext;

    //empty process list images
    ImageList_RemoveAll(pDlgContext->ImageList);

    //empty process list
    ListView_DeleteAllItems(GetDlgItem(hwndDlg, ID_PROCESSLIST));

    //set default app icon
    hIcon = LoadIcon(NULL, IDI_APPLICATION);

    if (hIcon) {
        ImageList_ReplaceIcon(pDlgContext->ImageList, -1, hIcon);
        DestroyIcon(hIcon);
    }

    //sort image up
    hIcon = (HICON)LoadImage(g_WinObj.hInstance,
        MAKEINTRESOURCE(IDI_ICON_SORTUP), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);

    if (hIcon) {
        ImageList_ReplaceIcon(pDlgContext->ImageList, -1, hIcon);
        DestroyIcon(hIcon);
    }

    //sort image down
    hIcon = (HICON)LoadImage(g_WinObj.hInstance,
        MAKEINTRESOURCE(IDI_ICON_SORTDOWN), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);

    if (hIcon) {
        ImageList_ReplaceIcon(pDlgContext->ImageList, -1, hIcon);
        DestroyIcon(hIcon);
    }

    //
    // Check if additional info is available.
    //
    if (Context->ObjectInfo.ObjectAddress != 0) {

        ObjectAddress = Context->ObjectInfo.ObjectAddress;

        ObjectTypeIndex = ObDecodeTypeIndex((PVOID)ObjectAddress,
            Context->ObjectInfo.ObjectHeader.TypeIndex);

        bObjectFound = TRUE;
    }

    do {
        //
        // When object address is unknown, open object and query it address.
        // This DesiredAccess flag is used to open currently viewed object.
        //
        if (ObjectAddress == 0) {

            DesiredAccess = READ_CONTROL;
            bObjectFound = FALSE;

            //
            // Open temporary object handle to query object address.
            //
            if (propOpenCurrentObject(Context, &hObject, DesiredAccess)) {

                pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation, NULL);
                if (pHandles) {

                    //
                    // Find our handle object by handle value.
                    //
                    bObjectFound = supQueryObjectFromHandleEx(pHandles,
                        hObject,
                        &ObjectAddress,
                        &ObjectTypeIndex);

                    supHeapFree(pHandles);
                }

                supCloseObjectFromContext(Context, hObject);
            }

        }

        //
        // Nothing to compare.
        //
        if (bObjectFound == FALSE)
            break;

        //
        // Take process and handles snapshot.
        //
        ProcessList = supGetSystemInfo(SystemProcessInformation, NULL);
        if (ProcessList == NULL)
            break;

        pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation, NULL);
        if (pHandles) {

            //
            // Find any handles with the same object address and object type.
            //
            enumContext.ImageList = pDlgContext->ImageList;
            enumContext.ListView = pDlgContext->ListView;
            enumContext.ProcessList = ProcessList;
            enumContext.ObjectAddress = ObjectAddress;
            enumContext.ObjectTypeIndex = ObjectTypeIndex;

            supListViewEnableRedraw(pDlgContext->ListView, FALSE);

            supEnumHandleDump(pHandles,
                (PENUMERATE_HANDLE_DUMP_CALLBACK)ProcessEnumHandlesCallback,
                &enumContext);

            supListViewEnableRedraw(pDlgContext->ListView, TRUE);

            supHeapFree(pHandles);
            pHandles = NULL;
        }


    } while (FALSE);

    //
    // Cleanup.
    //
    if (pHandles) {
        supHeapFree(pHandles);
    }
    if (ProcessList) {
        supHeapFree(ProcessList);
    }

    //
    // Show/hide notification text.
    //
    ShowWindow(GetDlgItem(hwndDlg, ID_PROCESSLISTNOALL), (ObjectAddress == 0) ? SW_SHOW : SW_HIDE);
}

/*
* ProcessInitListView
*
* Purpose:
*
* Initialize listview for process list.
* Called once.
*
*/
BOOL ProcessInitListView(
    _In_ HWND hwndDlg,
    _In_ EXTRASCONTEXT* pDlgContext
)
{
    LVCOLUMNS_DATA columnData[] =
    {
        { L"Process", 160, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,  2 },
        { L"ID", 60, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,  I_IMAGENONE },
        { L"Handle", 130, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,  I_IMAGENONE },
        { L"Access", 80, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,  I_IMAGENONE }
    };

    pDlgContext->ListView = GetDlgItem(hwndDlg, ID_PROCESSLIST);
    if (pDlgContext->ListView == NULL)
        return FALSE;

    pDlgContext->ImageList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 32, 8);

    //
    // Set listview imagelist, style flags and theme.
    //
    supSetListViewSettings(pDlgContext->ListView,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP,
        FALSE,
        TRUE,
        pDlgContext->ImageList,
        LVSIL_SMALL);

    //
    // And columns and remember their count.
    //
    pDlgContext->lvColumnCount = supAddLVColumnsFromArray(
        pDlgContext->ListView,
        columnData,
        RTL_NUMBER_OF(columnData));

    return TRUE;
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
    _In_ HWND hwndDlg,
    _In_ LPPOINT lpPoint,
    _In_ PVOID lpUserParam
)
{
    HMENU hMenu;
    EXTRASCONTEXT* Context = (EXTRASCONTEXT*)lpUserParam;

    hMenu = CreatePopupMenu();
    if (hMenu) {

        if (supListViewAddCopyValueItem(hMenu,
            Context->ListView,
            ID_OBJECT_COPY,
            0,
            lpPoint,
            &Context->lvItemHit,
            &Context->lvColumnHit))
        {
            TrackPopupMenu(hMenu,
                TPM_RIGHTBUTTON | TPM_LEFTALIGN,
                lpPoint->x,
                lpPoint->y,
                0,
                hwndDlg,
                NULL);
        }
        DestroyMenu(hMenu);
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
    PROPSHEETPAGE* pSheet = NULL;
    PROP_OBJECT_INFO* Context = NULL;
    EXTRASCONTEXT* pDlgContext = NULL;

    switch (uMsg) {

    case WM_CONTEXTMENU:

        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            supHandleContextMenuMsgForListView(hwndDlg,
                wParam,
                lParam,
                pDlgContext->ListView,
                (pfnPopupMenuHandler)ProcessHandlePopupMenu,
                pDlgContext);
        }
        break;

    case WM_COMMAND:

        if (GET_WM_COMMAND_ID(wParam, lParam) == ID_OBJECT_COPY) {
            pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
            if (pDlgContext) {

                supListViewCopyItemValueToClipboard(pDlgContext->ListView,
                    pDlgContext->lvItemHit,
                    pDlgContext->lvColumnHit);

            }
        }
        break;

    case WM_NOTIFY:
        return ProcessListHandleNotify(hwndDlg, lParam);

    case WM_DESTROY:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            if (pDlgContext->ImageList) {
                ImageList_Destroy(pDlgContext->ImageList);
            }
            supHeapFree(pDlgContext);
        }
        RemoveProp(hwndDlg, T_PROPCONTEXT);
        RemoveProp(hwndDlg, T_DLGCONTEXT);
        break;

    case WM_INITDIALOG:

        pSheet = (PROPSHEETPAGE*)lParam;
        if (pSheet) {
            Context = (PROP_OBJECT_INFO*)pSheet->lParam;
            SetProp(hwndDlg, T_PROPCONTEXT, (HANDLE)Context);

            pDlgContext = (EXTRASCONTEXT*)supHeapAlloc(sizeof(EXTRASCONTEXT));
            if (pDlgContext) {

                pDlgContext->lvColumnHit = -1;
                pDlgContext->lvItemHit = -1;

                SetProp(hwndDlg, T_DLGCONTEXT, (HANDLE)pDlgContext);

                if (ProcessInitListView(hwndDlg, pDlgContext)) {

                    ProcessListSetInfo(hwndDlg, Context, pDlgContext);

                    ListView_SortItemsEx(
                        pDlgContext->ListView,
                        &ProcessListCompareFunc,
                        pDlgContext);
                }
            }
        }
        break;

    default:
        return FALSE;
    }

    return TRUE;
}
