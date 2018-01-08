/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       PROPPROCESS.C
*
*  VERSION:     1.52
*
*  DATE:        08 Jan 2018
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "propDlg.h"

//number of columns, revise this unit code after any change to this number
#define PROCESSLIST_COLUMN_COUNT 4

//page imagelist
HIMAGELIST ProcessImageList = NULL;
//page listview
HWND g_hwndProcessList = NULL;
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
    INT       nResult = 0;
    LPWSTR    lpItem1 = NULL, lpItem2 = NULL;
    SIZE_T    cbItem1 = 0, cbItem2 = 0;
    ULONG_PTR Value1, Value2;

    USHORT AddressPrefix;

    lpItem1 = supGetItemText(
        g_hwndProcessList,
        (INT)lParam1,
        (INT)lParamSort,
        &cbItem1);

    if (lpItem1 == NULL) //can't be 0 for this dialog
        goto Done;

    lpItem2 = supGetItemText(
        g_hwndProcessList,
        (INT)lParam2,
        (INT)lParamSort,
        &cbItem2);

    if (lpItem2 == NULL) //can't be 0 for this dialog
        goto Done;

    switch (lParamSort) {
    case 0:
        //
        // Name column.
        //
        if (bProcessListSortInverse)
            nResult = _strcmpi(lpItem2, lpItem1);
        else
            nResult = _strcmpi(lpItem1, lpItem2);

        break;
    case 1:
        //
        // Id column.
        //
        Value1 = strtou64(lpItem1);
        Value2 = strtou64(lpItem2);
        if (bProcessListSortInverse)
            nResult = Value2 > Value1;
        else
            nResult = Value1 > Value2;
        break;

    case 2:
        //
        // Handle value colum.
        //
        if ((cbItem1 / sizeof(WCHAR) != MAX_ADDRESS_TEXT_LENGTH64) &&
            (cbItem2 / sizeof(WCHAR) != MAX_ADDRESS_TEXT_LENGTH64))
        {
            nResult = 0;
            break;
        }

        Value1 = 0;
        Value2 = 0;

        AddressPrefix = supIsAddressPrefix(lpItem1, cbItem1);
        if (AddressPrefix == 2)
            Value1 = hextou64(&lpItem1[AddressPrefix]);

        AddressPrefix = supIsAddressPrefix(lpItem2, cbItem2);
        if (AddressPrefix == 2)
            Value2 = hextou64(&lpItem2[AddressPrefix]);

        if (bProcessListSortInverse)
            nResult = Value2 > Value1;
        else
            nResult = Value1 > Value2;

        break;
    case 3:
        //
        // GrantedAccess column.
        //
        if ((cbItem1 / sizeof(WCHAR) != MAX_ADDRESS_TEXT_LENGTH32) &&
            (cbItem2 / sizeof(WCHAR) != MAX_ADDRESS_TEXT_LENGTH32))
        {
            nResult = 0;
            break;
        }

        Value1 = 0;
        Value2 = 0;

        AddressPrefix = supIsAddressPrefix(lpItem1, cbItem1);
        if (AddressPrefix == 2)
            Value1 = hextou64(&lpItem1[AddressPrefix]);

        AddressPrefix = supIsAddressPrefix(lpItem2, cbItem2);
        if (AddressPrefix == 2)
            Value2 = hextou64(&lpItem2[AddressPrefix]);

        if (bProcessListSortInverse)
            nResult = Value2 > Value1;
        else
            nResult = Value1 > Value2;

        break;

    default:
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
    _In_ INT iItem
)
{
    LPWSTR              Buffer;
    DWORD               dwProcessId;
    ULONG               bytesNeeded;
    HANDLE              hProcess;
    NTSTATUS            status;
    PUNICODE_STRING     dynUstr;
    OBJECT_ATTRIBUTES   obja;
    CLIENT_ID           cid;

    __try {
        //query process id
        Buffer = supGetItemText(g_hwndProcessList, iItem, 1, NULL);
        if (Buffer) {
            dwProcessId = strtoul(Buffer);
            supHeapFree(Buffer);

            //query process win32 image path
            //1. open target process
            cid.UniqueProcess = (HANDLE)dwProcessId; //-V204
            cid.UniqueThread = NULL;
            InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
            status = NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &obja, &cid);
            if (NT_SUCCESS(status)) {
                //2. query required buffer size
                bytesNeeded = 0;
                NtQueryInformationProcess(hProcess, ProcessImageFileNameWin32, NULL, 0, &bytesNeeded);
                if (bytesNeeded) {

                    Buffer = supHeapAlloc(bytesNeeded);
                    if (Buffer) {

                        //3. query win32 filename
                        status = NtQueryInformationProcess(hProcess,
                            ProcessImageFileNameWin32,
                            Buffer,
                            bytesNeeded,
                            &bytesNeeded);

                        if (NT_SUCCESS(status)) {
                            dynUstr = (PUNICODE_STRING)Buffer;
                            if (dynUstr->Buffer && dynUstr->Length) {
                                //4. shellexecute properties dialog
                                supShowProperties(hwndDlg, dynUstr->Buffer);
                            }
                        }
                        supHeapFree(Buffer);
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
    _In_ HWND hwndDlg,
    _In_ LPARAM lParam
)
{
    INT        c;
    LVCOLUMN   col;
    LPNMHDR    nhdr = (LPNMHDR)lParam;

    if (nhdr == NULL)
        return;

    if (nhdr->idFrom != ID_PROCESSLIST)
        return;

    switch (nhdr->code) {

    case LVN_COLUMNCLICK:
        bProcessListSortInverse = !bProcessListSortInverse;
        ProcessListSortColumn = ((NMLISTVIEW *)nhdr)->iSubItem;
        ListView_SortItemsEx(g_hwndProcessList, &ProcessListCompareFunc, ProcessListSortColumn);

        RtlSecureZeroMemory(&col, sizeof(col));
        col.mask = LVCF_IMAGE;
        col.iImage = -1;

        for (c = 0; c < PROCESSLIST_COLUMN_COUNT; c++)
            ListView_SetColumn(g_hwndProcessList, c, &col);

        if (bProcessListSortInverse)
            col.iImage = 1;
        else
            col.iImage = 2;

        ListView_SetColumn(g_hwndProcessList, ((NMLISTVIEW *)nhdr)->iSubItem, &col);
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
    _In_ ULONG_PTR ProcessId,
    _Out_ HICON *pProcessIcon,
    _Out_ BOOL *pbIs32
)
{
    BOOL               bResult = FALSE, bIconFound = FALSE;
    ULONG              bytesNeeded;
    HANDLE             hProcess;
    NTSTATUS           status;
    PVOID              Buffer;
    PUNICODE_STRING    dynUstr;
    CLIENT_ID          cid;
    OBJECT_ATTRIBUTES  obja;

    __try {
        *pProcessIcon = NULL;
        *pbIs32 = FALSE;

        cid.UniqueProcess = (HANDLE)ProcessId;
        cid.UniqueThread = NULL;

        InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
        status = NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &obja, &cid);
        if (!NT_SUCCESS(status))
            return bResult;

        //
        // Query process icon, first query win32 imagefilename then parse image resources.
        //
        bytesNeeded = 0;
        status = NtQueryInformationProcess(hProcess, ProcessImageFileNameWin32, NULL, 0, &bytesNeeded);
        if ((status == STATUS_INFO_LENGTH_MISMATCH) && (bytesNeeded)) {
            Buffer = supHeapAlloc(bytesNeeded);
            if (Buffer) {

                status = NtQueryInformationProcess(hProcess,
                    ProcessImageFileNameWin32,
                    Buffer,
                    bytesNeeded,
                    &bytesNeeded);

                if (NT_SUCCESS(status)) {
                    dynUstr = (PUNICODE_STRING)Buffer;
                    if (dynUstr->Buffer && dynUstr->Length) {
                        *pProcessIcon = supGetMainIcon(dynUstr->Buffer, 16, 16);
                        bIconFound = TRUE;
                    }
                }
                supHeapFree(Buffer);
            }
        }

        //
        // Query if this is wow64 process.
        //
        *pbIs32 = supIsProcess32bit(hProcess);

        NtClose(hProcess);
    }
    __except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
        return FALSE;
    }
    bResult = (bIconFound);
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

    if (supQueryProcessName(phti->UniqueProcessId,
        ProcessesList,
        szBuffer,
        MAX_PATH))
    {
        //
        // Id exists, extract icon
        // Skip idle, system
        //
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
            }
        }
    }

    //
    // Process Name.
    //
    RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
    lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
    lvitem.iImage = iImage;
    lvitem.iSubItem = 0;
    lvitem.pszText = szBuffer;
    lvitem.iItem = MAXINT;
    nIndex = ListView_InsertItem(g_hwndProcessList, &lvitem);

    //
    // ProcessId.
    //
    RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
    u64tostr(phti->UniqueProcessId, szBuffer);
    lvitem.mask = LVIF_TEXT;
    lvitem.iSubItem = 1;
    lvitem.pszText = szBuffer;
    lvitem.iItem = nIndex;
    ListView_SetItem(g_hwndProcessList, &lvitem);

    //
    // Handle Value.
    //
    RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
    _strcpy(szBuffer, L"0x");
    u64tohex(phti->HandleValue, _strend(szBuffer));
    lvitem.mask = LVIF_TEXT;
    lvitem.iSubItem = 2;
    lvitem.pszText = szBuffer;
    lvitem.iItem = nIndex;
    ListView_SetItem(g_hwndProcessList, &lvitem);

    //
    // Handle GrantedAccess.
    //
    RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
    _strcpy(szBuffer, L"0x");
    ultohex(phti->GrantedAccess, _strend(szBuffer));
    lvitem.mask = LVIF_TEXT;
    lvitem.iSubItem = 3;
    lvitem.pszText = szBuffer;
    lvitem.iItem = nIndex;
    ListView_SetItem(g_hwndProcessList, &lvitem);
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
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    BOOL                            cond = FALSE;
    USHORT                          ObjectTypeIndex;
    ULONG                           i;
    DWORD                           CurrentProcessId = GetCurrentProcessId();
    ULONG_PTR                       ObjectAddress;
    ACCESS_MASK                     DesiredAccess;
    PVOID                           ProcessesList;
    HANDLE                          hObject, hIcon;
    PSYSTEM_HANDLE_INFORMATION_EX   pHandles;

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
    hIcon = LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(IDI_ICON_SORTUP), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
    if (hIcon) {
        ImageList_ReplaceIcon(ProcessImageList, -1, hIcon);
        DestroyIcon(hIcon);
    }
    hIcon = LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(IDI_ICON_SORTDOWN), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
    if (hIcon) {
        ImageList_ReplaceIcon(ProcessImageList, -1, hIcon);
        DestroyIcon(hIcon);
    }

    //check if additional info available
    if (Context->ObjectInfo.ObjectAddress != 0) {
        ObjectAddress = Context->ObjectInfo.ObjectAddress;
        ObjectTypeIndex = ObDecodeTypeIndex((PVOID)ObjectAddress, Context->ObjectInfo.ObjectHeader.TypeIndex);
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
            case TYPE_MEMORYPARTITION:
                DesiredAccess = MEMORY_PARTITION_QUERY_ACCESS;
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

        pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation);
        if (pHandles == NULL)
            break;

        ProcessesList = supGetSystemInfo(SystemProcessInformation);
        if (ProcessesList == NULL)
            break;

        //no additional info available which mean we must query object address by yourself
        if (ObjectAddress == 0) {
            //find our handle object by handle value
            for (i = 0; i < pHandles->NumberOfHandles; i++)
                if (pHandles->Handles[i].UniqueProcessId == CurrentProcessId)
                    if (pHandles->Handles[i].HandleValue == (ULONG_PTR)hObject) {
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
        supHeapFree(pHandles);
        pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation);
        if (pHandles == NULL)
            break;

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
        supHeapFree(pHandles);
    }
    if (ProcessesList) {
        supHeapFree(ProcessesList);
    }
    if ((Context->TypeIndex == TYPE_WINSTATION) && (hObject != NULL)) {
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
    LVCOLUMN col;

    g_hwndProcessList = GetDlgItem(hwndDlg, ID_PROCESSLIST);
    if (g_hwndProcessList == NULL)
        return;

    ProcessImageList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 32, 8);
    if (ProcessImageList) {
        ListView_SetImageList(g_hwndProcessList, ProcessImageList, LVSIL_SMALL);
    }

    ListView_SetExtendedListViewStyle(g_hwndProcessList, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

    RtlSecureZeroMemory(&col, sizeof(col));
    col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER | LVCF_IMAGE;
    col.iSubItem++;
    col.pszText = TEXT("Process");
    col.fmt = LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT;
    col.iImage = 2;
    col.cx = 160;
    ListView_InsertColumn(g_hwndProcessList, col.iSubItem, &col);

    col.iSubItem++;
    col.pszText = TEXT("ID");
    col.iOrder++;
    col.iImage = -1;
    col.cx = 60;
    ListView_InsertColumn(g_hwndProcessList, col.iSubItem, &col);

    col.iSubItem++;
    col.pszText = TEXT("Handle");
    col.iOrder++;
    col.cx = 130;
    ListView_InsertColumn(g_hwndProcessList, col.iSubItem, &col);

    col.iSubItem++;
    col.pszText = TEXT("Access");
    col.iOrder++;
    col.cx = 80;
    ListView_InsertColumn(g_hwndProcessList, col.iSubItem, &col);
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

    if (GetCursorPos(&pt1) == FALSE)
        return;

    hMenu = CreatePopupMenu();
    if (hMenu) {
        InsertMenu(hMenu, 0, MF_BYCOMMAND, ID_OBJECT_COPY, T_COPYTEXTROW);
        TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, pt1.x, pt1.y, 0, hwndDlg, NULL);
        DestroyMenu(hMenu);
    }
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
    INT     nSelection, i;
    SIZE_T  cbText, sz;
    LPWSTR  lpText, lpItemText[4];
    HWND    hwndList;

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
        lpText = supHeapAlloc(cbText);
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
            supHeapFree(lpText);
        }
        for (i = 0; i < PROCESSLIST_COLUMN_COUNT; i++) {
            if (lpItemText[i] != NULL) {
                supHeapFree(lpItemText[i]);
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
    PROPSHEETPAGE    *pSheet = NULL;
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
            if (g_hwndProcessList) {
                ProcessListSetInfo(Context, hwndDlg);
                ListView_SortItemsEx(g_hwndProcessList, &ProcessListCompareFunc, ProcessListSortColumn);
            }

        }
        return 1;
        break;

    }
    return 0;
}
