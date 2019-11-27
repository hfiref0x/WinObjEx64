/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019
*
*  TITLE:       PROPPROCESS.C
*
*  VERSION:     1.82
*
*  DATE:        18 Nov 2019
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

//number of columns, revise this unit code after any change to this number
#define PROCESSLIST_COLUMN_COUNT 4

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
    LPWSTR    lpItem1 = NULL, lpItem2 = NULL;
    ULONG_PTR Value1, Value2;

    LPARAM lvColumnToSort;

    EXTRASCONTEXT *pDlgContext;

    pDlgContext = (EXTRASCONTEXT*)lpContextParam;
    if (pDlgContext == NULL)
        return 0;

    lvColumnToSort = (LPARAM)pDlgContext->lvColumnToSort;

    //
    // Sort Handle/GrantedAccess value column.
    //
    if ((lvColumnToSort == 2) || (lvColumnToSort == 3)) {
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
    case 0:
        //
        // Name column.
        //
        if (pDlgContext->bInverseSort)
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
        if (pDlgContext->bInverseSort)
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
    _In_ HWND hwndListView,
    _In_ INT iItem
)
{
    LPWSTR              Buffer;
    ULONG               bytesNeeded;
    HANDLE              UniqueProcessId;
    HANDLE              hProcess;
    NTSTATUS            status;
    PUNICODE_STRING     dynUstr;
    OBJECT_ATTRIBUTES   obja;
    CLIENT_ID           cid;

    __try {
        //query process id
        Buffer = supGetItemText(hwndListView, iItem, 1, NULL);
        if (Buffer) {
            UniqueProcessId = UlongToHandle(strtoul(Buffer));
            supHeapFree(Buffer);

            //query process win32 image path
            //1. open target process
            cid.UniqueProcess = UniqueProcessId;
            cid.UniqueThread = NULL;
            InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
            status = NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &obja, &cid);
            if (NT_SUCCESS(status)) {
                //2. query required buffer size
                bytesNeeded = 0;
                NtQueryInformationProcess(hProcess, ProcessImageFileNameWin32, NULL, 0, &bytesNeeded);
                if (bytesNeeded) {

                    Buffer = (LPWSTR)supHeapAlloc((SIZE_T)bytesNeeded + sizeof(UNICODE_NULL));
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
    INT     nImageIndex;
    LPNMHDR nhdr = (LPNMHDR)lParam;

    EXTRASCONTEXT *pDlgContext;

    if (nhdr == NULL)
        return;

    if (nhdr->idFrom != ID_PROCESSLIST)
        return;

    switch (nhdr->code) {

    case LVN_COLUMNCLICK:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            pDlgContext->bInverseSort = !pDlgContext->bInverseSort;
            pDlgContext->lvColumnToSort = ((NMLISTVIEW *)nhdr)->iSubItem;

            ListView_SortItemsEx(
                pDlgContext->ListView,
                &ProcessListCompareFunc,
                pDlgContext);

            if (pDlgContext->bInverseSort)
                nImageIndex = 1;
            else
                nImageIndex = 2;

            supUpdateLvColumnHeaderImage(
                pDlgContext->ListView,
                pDlgContext->lvColumnCount,
                pDlgContext->lvColumnToSort,
                nImageIndex);
        }
        break;

    case NM_DBLCLK:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {

            ProcessShowProperties(
                hwndDlg,
                pDlgContext->ListView,
                ((LPNMITEMACTIVATE)lParam)->iItem);
        }
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
            Buffer = supHeapAlloc((SIZE_T)bytesNeeded + sizeof(UNICODE_NULL));
            if (Buffer) {

                status = NtQueryInformationProcess(
                    hProcess,
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
        if (phti->UniqueProcessId <= 4) {
            iImage = 0;
        }
        else {
            hIcon = NULL;
            bIsWow64 = FALSE;
            if (ProcessQueryInfo(phti->UniqueProcessId, &hIcon, &bIsWow64)) {
                if (hIcon) {
                    iImage = ImageList_ReplaceIcon(ImageList, -1, hIcon);
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
    nIndex = ListView_InsertItem(hwndListView, &lvitem);

    //
    // ProcessId.
    //
    RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
    u64tostr(phti->UniqueProcessId, szBuffer);
    lvitem.mask = LVIF_TEXT;
    lvitem.iSubItem = 1;
    lvitem.pszText = szBuffer;
    lvitem.iItem = nIndex;
    ListView_SetItem(hwndListView, &lvitem);

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
    ListView_SetItem(hwndListView, &lvitem);

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
    ListView_SetItem(hwndListView, &lvitem);
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
    _In_ PROP_OBJECT_INFO *Context,
    _In_ EXTRASCONTEXT *pDlgContext
)
{
    USHORT                          ObjectTypeIndex = 0;
    ULONG                           i;
    DWORD                           CurrentProcessId = GetCurrentProcessId();
    ULONG_PTR                       ObjectAddress = 0;
    ACCESS_MASK                     DesiredAccess;
    PVOID                           ProcessesList = NULL;
    HANDLE                          hObject = NULL;
    HICON                           hIcon;
    PSYSTEM_HANDLE_INFORMATION_EX   pHandles = NULL;

    if (Context == NULL) {
        return;
    }

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
    //sort images
    hIcon = (HICON)LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(IDI_ICON_SORTUP), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
    if (hIcon) {
        ImageList_ReplaceIcon(pDlgContext->ImageList, -1, hIcon);
        DestroyIcon(hIcon);
    }
    hIcon = (HICON)LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(IDI_ICON_SORTDOWN), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
    if (hIcon) {
        ImageList_ReplaceIcon(pDlgContext->ImageList, -1, hIcon);
        DestroyIcon(hIcon);
    }

    //check if additional info available
    if (Context->ObjectInfo.ObjectAddress != 0) {
        ObjectAddress = Context->ObjectInfo.ObjectAddress;
        ObjectTypeIndex = ObDecodeTypeIndex((PVOID)ObjectAddress, Context->ObjectInfo.ObjectHeader.TypeIndex);
    }

    do {
        //
        // When object address is unknown, open object and query it address.
        // These DesiredAccess flag is used to open currently viewed object,
        // here listed access rights for each object properties dialog 
        // where "Process" tab included.
        //
        if (ObjectAddress == 0) {
            switch (Context->TypeIndex) {
            case ObjectTypeSection:
                DesiredAccess = SECTION_QUERY;
                break;
            case ObjectTypeSymbolicLink:
                DesiredAccess = SYMBOLIC_LINK_QUERY;
                break;
            case ObjectTypeEvent:
                DesiredAccess = EVENT_QUERY_STATE;
                break;
            case ObjectTypeJob:
                DesiredAccess = JOB_OBJECT_QUERY;
                break;
            case ObjectTypeMutant:
                DesiredAccess = MUTANT_QUERY_STATE;
                break;
            case ObjectTypeDirectory:
                DesiredAccess = DIRECTORY_QUERY;
                break;
            case ObjectTypeWinstation:
                DesiredAccess = WINSTA_READATTRIBUTES;
                break;
            case ObjectTypeSemaphore:
                DesiredAccess = SEMAPHORE_QUERY_STATE;
                break;
            case ObjectTypeTimer:
                DesiredAccess = TIMER_QUERY_STATE;
                break;
            case ObjectTypeSession:
                DesiredAccess = SESSION_QUERY_ACCESS;
                break;
            case ObjectTypeIoCompletion:
                DesiredAccess = IO_COMPLETION_QUERY_STATE;
                break;
            case ObjectTypeMemoryPartition:
                DesiredAccess = MEMORY_PARTITION_QUERY_ACCESS;
                break;
            case ObjectTypeToken:
                DesiredAccess = TOKEN_QUERY;
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

        pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation, NULL);
        if (pHandles == NULL)
            break;

        ProcessesList = supGetSystemInfo(SystemProcessInformation, NULL);
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
        pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation, NULL);
        if (pHandles == NULL)
            break;

        //find any handles with the same object address and object type
        for (i = 0; i < pHandles->NumberOfHandles; i++)
            if (pHandles->Handles[i].ObjectTypeIndex == ObjectTypeIndex) {
                if ((ULONG_PTR)pHandles->Handles[i].Object == ObjectAddress) {

                    //
                    // Decode and add information to the list.
                    //
                    ProcessListAddItem(
                        pDlgContext->ListView,
                        pDlgContext->ImageList,
                        ProcessesList,
                        &pHandles->Handles[i]);
                }
            }

    } while (FALSE);

    //cleanup
    if (pHandles) {
        supHeapFree(pHandles);
    }
    if (ProcessesList) {
        supHeapFree(ProcessesList);
    }

    if (hObject) {

        if (Context->TypeIndex == ObjectTypeWinstation)
            CloseWindowStation((HWINSTA)hObject);
        else
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
    _In_ HWND hwndDlg,
    _In_ EXTRASCONTEXT* pDlgContext
)
{
    LVCOLUMN col;

    pDlgContext->ListView = GetDlgItem(hwndDlg, ID_PROCESSLIST);
    if (pDlgContext->ListView == NULL)
        return;

    pDlgContext->ImageList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 32, 8);
    if (pDlgContext->ImageList) {
        ListView_SetImageList(pDlgContext->ListView, pDlgContext->ImageList, LVSIL_SMALL);
    }

    ListView_SetExtendedListViewStyle(
        pDlgContext->ListView,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

    SetWindowTheme(pDlgContext->ListView, TEXT("Explorer"), NULL);

    RtlSecureZeroMemory(&col, sizeof(col));
    col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER | LVCF_IMAGE;
    col.iSubItem++;
    col.pszText = TEXT("Process");
    col.fmt = LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT;
    col.iImage = 2;
    col.cx = 160;
    ListView_InsertColumn(pDlgContext->ListView, col.iSubItem, &col);

    col.iImage = I_IMAGENONE;

    col.iSubItem++;
    col.pszText = TEXT("ID");
    col.iOrder++;
    col.cx = 60;
    ListView_InsertColumn(pDlgContext->ListView, col.iSubItem, &col);

    col.iSubItem++;
    col.pszText = TEXT("Handle");
    col.iOrder++;
    col.cx = 130;
    ListView_InsertColumn(pDlgContext->ListView, col.iSubItem, &col);

    col.iSubItem++;
    col.pszText = TEXT("Access");
    col.iOrder++;
    col.cx = 80;
    ListView_InsertColumn(pDlgContext->ListView, col.iSubItem, &col);

    pDlgContext->lvColumnCount = PROCESSLIST_COLUMN_COUNT;
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
    _In_ HWND hwndList,
    _In_ INT lvComlumnCount
)
{
    INT     nSelection, i;
    SIZE_T  cbText, sz;
    LPWSTR  lpText, lpItemText[4];

    if (ListView_GetSelectedCount(hwndList) == 0) {
        return;
    }

    nSelection = ListView_GetSelectionMark(hwndList);
    if (nSelection == -1) {
        return;
    }

    __try {
        cbText = 0;
        for (i = 0; i < lvComlumnCount; i++) {
            sz = 0;
            lpItemText[i] = supGetItemText(hwndList, nSelection, i, &sz);
            cbText += sz;
        }

        cbText += (lvComlumnCount * sizeof(WCHAR)) + sizeof(UNICODE_NULL);
        lpText = (LPWSTR)supHeapAlloc(cbText);
        if (lpText) {

            for (i = 0; i < lvComlumnCount; i++) {
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
        for (i = 0; i < lvComlumnCount; i++) {
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
    EXTRASCONTEXT    *pDlgContext = NULL;

    switch (uMsg) {

    case WM_CONTEXTMENU:
        ProcessHandlePopupMenu(hwndDlg);
        break;

    case WM_COMMAND:

        if (LOWORD(wParam) == ID_OBJECT_COPY) {
            pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
            if (pDlgContext) {
                ProcessCopyText(pDlgContext->ListView, pDlgContext->lvColumnCount);
            }
        }
        break;

    case WM_NOTIFY:
        ProcessListHandleNotify(hwndDlg, lParam);
        return 1;
        break;

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

        pSheet = (PROPSHEETPAGE *)lParam;
        if (pSheet) {
            Context = (PROP_OBJECT_INFO *)pSheet->lParam;
            SetProp(hwndDlg, T_PROPCONTEXT, (HANDLE)Context);

            pDlgContext = (EXTRASCONTEXT*)supHeapAlloc(sizeof(EXTRASCONTEXT));
            if (pDlgContext) {
                SetProp(hwndDlg, T_DLGCONTEXT, (HANDLE)pDlgContext);

                ProcessListCreate(hwndDlg, pDlgContext);
                if (pDlgContext->ListView) {

                    ProcessListSetInfo(hwndDlg, Context, pDlgContext);

                    ListView_SortItemsEx(
                        pDlgContext->ListView,
                        &ProcessListCompareFunc,
                        pDlgContext);
                }
            }
        }
        return 1;
        break;

    }
    return 0;
}
