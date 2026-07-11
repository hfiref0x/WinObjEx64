/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022 - 2026
*
*  TITLE:       EXTRASCMOPT.C
*
*  VERSION:     2.11
*
*  DATE:        11 Jul 2026
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "extras.h"

#define T_DUMP_VALUE TEXT("Dump Value to File")

#define ID_CMOPTLIST_SAVE 40060
#define ID_CMOPTLIST_DUMP 40061

#define CMOPTDLG_TRACKSIZE_MIN_X 640
#define CMOPTDLG_TRACKSIZE_MIN_Y 480

#define COLUMN_CMOPTLIST_KEY_NAME               0
#define COLUMN_CMOPTLIST_VALUE_NAME             1
#define COLUMN_CMOPTLIST_BUFFER                 2
#define COLUMN_CMOPTLIST_BUFFER_LENGTH          3
#define COLUM_CMOPTLIST_VALUE_MEMORY            5

static HANDLE CmOptThreadHandle = NULL;
static EXTRASCONTEXT CmOptDlgContext;
static FAST_EVENT CmOptInitializedEvent = FAST_EVENT_INIT;

/*
* CmOptDlgDumpValueToFile
*
* Purpose:
*
* Dump selected value from kernel memory to the file.
*
*/
VOID CmOptDlgDumpValueToFile(
    _In_ HWND hwndDlg,
    _In_ HWND ListView,
    _In_ INT iItem
)
{
    BOOL bSuccess = FALSE;
    WCHAR szBuffer[MAX_PATH + 1];
    ULONG_PTR variableAddress;
    ULONG variableSize, bytesRead = 0;
    PBYTE tempBuffer = NULL;

    do {

        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));

        supGetItemText2(
            ListView,
            iItem,
            COLUMN_CMOPTLIST_BUFFER,
            szBuffer,
            MAX_TEXT_CONVERSION_ULONG64);

        variableAddress = hextou64(&szBuffer[2]);
        if (variableAddress < g_kdctx.SystemRangeStart)
            break;

        szBuffer[0] = 0;
        supGetItemText2(
            ListView,
            iItem,
            COLUMN_CMOPTLIST_BUFFER_LENGTH,
            szBuffer,
            MAX_TEXT_CONVERSION_ULONG64);

        variableSize = hextoul(&szBuffer[2]);
        if (variableSize >= 128 * 1024)
            break;

        if (variableSize == 0)
            variableSize = sizeof(ULONG);

        tempBuffer = (PBYTE)supHeapAlloc(ALIGN_UP_BY(variableSize, PAGE_SIZE));
        if (tempBuffer == NULL)
            break;

        //
        // Run Save As Dialog.
        //
        _strcpy(szBuffer, TEXT("dump.bin"));
        if (!supSaveDialogExecute(hwndDlg, szBuffer, TEXT("All files\0*.*\0\0"))) {
            bSuccess = TRUE; //user cancelled
            break;
        }

        if (kdReadSystemMemoryEx(variableAddress,
            tempBuffer,
            variableSize,
            &bytesRead))
        {
            if (bytesRead == variableSize) {

                bSuccess = (bytesRead == supWriteBufferToFile(szBuffer,
                    tempBuffer,
                    bytesRead,
                    FALSE,
                    FALSE,
                    NULL));

            }
        }

    } while (FALSE);

    if (bSuccess == FALSE) {
        MessageBox(
            hwndDlg,
            TEXT("Error dumping value"),
            PROGRAM_NAME,
            MB_ICONERROR);
    }

    if (tempBuffer) supHeapFree(tempBuffer);
}

/*
* CmOptDlgHandlePopupMenu
*
* Purpose:
*
* Table list popup construction.
*
*/
VOID CmOptDlgHandlePopupMenu(
    _In_ HWND hwndDlg,
    _In_ LPPOINT lpPoint,
    _In_ PVOID lpUserParam
)
{
    BOOLEAN bIoDriverLoaded;
    HMENU hMenu;
    UINT uPos = 0;
    EXTRASCONTEXT* Context = (EXTRASCONTEXT*)lpUserParam;

    hMenu = CreatePopupMenu();
    if (hMenu) {

        if (supListViewAddCopyValueItem(hMenu,
            Context->ListView,
            ID_OBJECT_COPY,
            uPos,
            lpPoint,
            &Context->lvItemHit,
            &Context->lvColumnHit))
        {
            InsertMenu(hMenu, ++uPos, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
        }

        bIoDriverLoaded = (Context->Reserved != 0);
        if (bIoDriverLoaded) {
            InsertMenu(hMenu, ++uPos, MF_BYCOMMAND, ID_CMOPTLIST_DUMP, T_DUMP_VALUE);
        }
        InsertMenu(hMenu, ++uPos, MF_BYCOMMAND, ID_CMOPTLIST_SAVE, T_EXPORTTOFILE);

        //
        // Track.
        //
        TrackPopupMenu(hMenu,
            TPM_RIGHTBUTTON | TPM_LEFTALIGN,
            lpPoint->x,
            lpPoint->y,
            0,
            hwndDlg,
            NULL);

        DestroyMenu(hMenu);
    }
}


/*
* CmOptDlgCompareFunc
*
* Purpose:
*
* CmControlVector listview comparer function.
*
*/
INT CALLBACK CmOptDlgCompareFunc(
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort
)
{
    EXTRASCONTEXT* pDlgContext = (EXTRASCONTEXT*)lParamSort;

    if (pDlgContext == NULL)
        return 0;

    switch (pDlgContext->lvColumnToSort) {

    case COLUMN_CMOPTLIST_KEY_NAME:
    case COLUMN_CMOPTLIST_VALUE_NAME:
        return supGetMaxCompareTwoFixedStrings(
            pDlgContext->ListView,
            lParam1,
            lParam2,
            pDlgContext->lvColumnToSort,
            pDlgContext->bInverseSort);

    case COLUMN_CMOPTLIST_BUFFER:
        return supGetMaxOfTwoU64FromHex(
            pDlgContext->ListView,
            lParam1,
            lParam2,
            pDlgContext->lvColumnToSort,
            pDlgContext->bInverseSort);

    default:
        return supGetMaxOfTwoUlongFromHex(
            pDlgContext->ListView,
            lParam1,
            lParam2,
            pDlgContext->lvColumnToSort,
            pDlgContext->bInverseSort);
    }

}

/*
* CmOptDlgHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for CmControlVector list dialog.
*
*/
BOOL CALLBACK CmOptDlgHandleNotify(
    _In_ LPNMLISTVIEW NMListView,
    _In_ EXTRASCONTEXT* Context
)
{
    INT nImageIndex;

    if (NMListView->hdr.idFrom != ID_EXTRASLIST)
        return FALSE;

    switch (NMListView->hdr.code) {

    case LVN_COLUMNCLICK:

        Context->bInverseSort = (~Context->bInverseSort) & 1;
        Context->lvColumnToSort = NMListView->iSubItem;

        ListView_SortItemsEx(Context->ListView,
            CmOptDlgCompareFunc,
            Context);

        nImageIndex = ImageList_GetImageCount(g_ListViewImages);
        if (Context->bInverseSort)
            nImageIndex -= 2; //sort down/up images are always at the end of main imagelist
        else
            nImageIndex -= 1;

        supUpdateLvColumnHeaderImage(
            Context->ListView,
            Context->lvColumnCount,
            Context->lvColumnToSort,
            nImageIndex);

        return TRUE;
    }

    return FALSE;
}

/*
* CmOptDlgHandleWMCommand
*
* Purpose:
*
* WM_COMMAND handler.
*
*/
VOID CmOptDlgHandleWMCommand(
    _In_ HWND hwndDlg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    UNREFERENCED_PARAMETER(lParam);

    switch (GET_WM_COMMAND_ID(wParam, lParam)) {

    case ID_OBJECT_COPY:

        supListViewCopyItemValueToClipboard(CmOptDlgContext.ListView,
            CmOptDlgContext.lvItemHit,
            CmOptDlgContext.lvColumnHit);

        break;

    case ID_CMOPTLIST_SAVE:

        supListViewExportToFile(
            TEXT("CmControlVector.csv"),
            hwndDlg,
            CmOptDlgContext.ListView);
        break;

    case ID_CMOPTLIST_DUMP:

        if (CmOptDlgContext.lvItemHit >= 0) {
            CmOptDlgDumpValueToFile(hwndDlg,
                CmOptDlgContext.ListView,
                CmOptDlgContext.lvItemHit);
        }

        break;

    case IDCANCEL:
        SendMessage(hwndDlg, WM_CLOSE, 0, 0);
        break;

    }
}

/*
* CmpOptDlgAddEntry
*
* Purpose:
*
* Adds CmControlVector entry to the listview.
*
*/
VOID CmpOptDlgAddEntry(
    _In_ HWND hwndList,
    _In_ PVOID pvEntry,
    _In_ ULONG ulEntrySize,
    _In_ BOOLEAN bIoDriverLoaded
)
{
    PBYTE  address;
    ULONG  value;
    INT    lvItemIndex;
    LVITEM lvitem;
    WCHAR  szBuffer[MAX_PATH + 1];

    union {
        union {
            CM_SYSTEM_CONTROL_VECTOR_V1* v1;
            CM_SYSTEM_CONTROL_VECTOR_V2* v2;
        } Version;
        PBYTE Ref;
    } CmControlVector;

    CmControlVector.Ref = (PBYTE)pvEntry;

    __try { //rely on undocumented structures

        RtlSecureZeroMemory(&lvitem, sizeof(lvitem));

        //
        // KeyName
        //
        lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
        lvitem.iItem = MAXINT;
        lvitem.pszText = CmControlVector.Version.v1->KeyPath;
        lvitem.iImage = g_TypeKey.ImageIndex;
        lvItemIndex = ListView_InsertItem(hwndList, &lvitem);
        if (lvItemIndex == -1)
            return;

        //
        // ValueName
        //
        lvitem.mask = LVIF_TEXT;
        lvitem.iSubItem++;
        lvitem.pszText = CmControlVector.Version.v1->ValueName;
        lvitem.iItem = lvItemIndex;
        ListView_SetItem(hwndList, &lvitem);

        //
        // Buffer
        //
        address = (PBYTE)CmControlVector.Version.v1->Buffer;
        if (address) {
            address = (ULONG_PTR)g_kdctx.NtOsBase + address - (ULONG_PTR)g_kdctx.NtOsImageMap;
        }
        szBuffer[0] = L'0';
        szBuffer[1] = L'x';
        szBuffer[2] = 0;
        u64tohex((ULONG_PTR)address, &szBuffer[2]);
        lvitem.iSubItem++;
        lvitem.pszText = szBuffer;
        lvitem.iItem = lvItemIndex;
        ListView_SetItem(hwndList, &lvitem);

        //
        // BufferLength
        //
        szBuffer[0] = L'0';
        szBuffer[1] = L'x';
        szBuffer[2] = 0;
        value = 0;
        if (CmControlVector.Version.v1->BufferLength) {
            value = *CmControlVector.Version.v1->BufferLength;
        }

        ultohex(value, &szBuffer[2]);
        lvitem.iSubItem++;
        lvitem.pszText = szBuffer;
        lvitem.iItem = lvItemIndex;
        ListView_SetItem(hwndList, &lvitem);

        //
        // Type
        //
        szBuffer[0] = L'0';
        szBuffer[1] = L'x';
        szBuffer[2] = 0;
        value = 0;
        if (CmControlVector.Version.v1->Type) {
            value = *CmControlVector.Version.v1->Type;
        }
        ultohex(value, &szBuffer[2]);

        lvitem.iSubItem++;
        lvitem.pszText = szBuffer;
        lvitem.iItem = lvItemIndex;
        ListView_SetItem(hwndList, &lvitem);

        //
        // Value
        //
        if (bIoDriverLoaded) {
            szBuffer[0] = 0;
            if (address) {

                value = 0;
                if (kdReadSystemMemory((ULONG_PTR)address, &value, sizeof(ULONG))) {
                    szBuffer[0] = L'0';
                    szBuffer[1] = L'x';
                    szBuffer[2] = 0;
                    ultohex(value, &szBuffer[2]);
                }

            }
            lvitem.iSubItem++;
            lvitem.pszText = szBuffer;
            lvitem.iItem = lvItemIndex;
            ListView_SetItem(hwndList, &lvitem);
        }

        //
        // Flags
        //
        if (ulEntrySize > sizeof(CM_SYSTEM_CONTROL_VECTOR_V1)) {

            szBuffer[0] = L'0';
            szBuffer[1] = L'x';
            szBuffer[2] = 0;
            ultohex(CmControlVector.Version.v2->Flags, &szBuffer[2]);

            lvitem.iSubItem++;
            lvitem.pszText = szBuffer;
            lvitem.iItem = lvItemIndex;
            ListView_SetItem(hwndList, &lvitem);
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return;
    }
}

/*
* CmOptDlgListOptions
*
* Purpose:
*
* Output CmControlVector data.
*
*/
VOID CmOptDlgListOptions(
    _In_ EXTRASCONTEXT* Context
)
{
    HWND   hwndList = Context->ListView;

    ULONG size;
    WCHAR  szBuffer[MAX_PATH + 1];

    union {
        union {
            CM_SYSTEM_CONTROL_VECTOR_V1* v1;
            CM_SYSTEM_CONTROL_VECTOR_V2* v2;
        } Version;
        PBYTE Ref;
    } CmControlVector;

    if (g_kdctx.Data->CmControlVector == NULL)
        g_kdctx.Data->CmControlVector = kdQueryCmControlVector(&g_kdctx);

    if (g_kdctx.Data->CmControlVector == NULL) {
        supStatusBarSetText(Context->StatusBar, 1, TEXT("Failed to query CmControlVector"));
        return;
    }

    CmControlVector.Ref = (PBYTE)g_kdctx.Data->CmControlVector;

    if (g_NtBuildNumber >= NT_WIN10_REDSTONE4)
        size = sizeof(CM_SYSTEM_CONTROL_VECTOR_V2);
    else
        size = sizeof(CM_SYSTEM_CONTROL_VECTOR_V1);

    supDisableRedraw(hwndList);

    while (CmControlVector.Version.v1->KeyPath != NULL) {
        CmpOptDlgAddEntry(hwndList, CmControlVector.Ref, size, (Context->Reserved != 0));
        CmControlVector.Ref += size;
    }

    ListView_SortItemsEx(hwndList,
        &CmOptDlgCompareFunc,
        (LPARAM)Context);

    supEnableRedraw(hwndList);

    _strcpy(szBuffer, TEXT("Total: "));
    ultostr(ListView_GetItemCount(Context->ListView), _strend(szBuffer));
    supStatusBarSetText(Context->StatusBar, 0, szBuffer);
}

/*
* CmOptDlgOnInit
*
* Purpose:
*
* WM_INITDIALOG handler.
*
*/
VOID CmOptDlgOnInit(
    _In_ HWND hwndDlg
)
{
    INT iImage = ImageList_GetImageCount(g_ListViewImages) - 1, iColumn;
    BOOLEAN bIoDriverLoaded;
    LVCOLUMNS_DATA columnDataList[] =
    {
        { L"KeyPath", 200, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT, iImage },
        { L"ValueName", 160, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT, I_IMAGENONE },
        { L"Buffer", 130, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT, I_IMAGENONE },
        { L"Length", 80, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT, I_IMAGENONE },
        { L"Type", 80, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT, I_IMAGENONE }
    };

    CmOptDlgContext.hwndDlg = hwndDlg;
    CmOptDlgContext.lvItemHit = -1;
    CmOptDlgContext.lvColumnHit = -1;

    extrasSetDlgIcon(&CmOptDlgContext);

    CmOptDlgContext.StatusBar = GetDlgItem(hwndDlg, ID_EXTRASLIST_STATUSBAR);
    CmOptDlgContext.ListView = GetDlgItem(hwndDlg, ID_EXTRASLIST);
    CmOptDlgContext.lvColumnHit = -1;
    CmOptDlgContext.lvItemHit = -1;

    //
    // Set listview imagelist, style flags and theme.
    //
    supSetListViewSettings(CmOptDlgContext.ListView,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP,
        FALSE,
        TRUE,
        g_ListViewImages,
        LVSIL_SMALL);

    //
    // And columns and remember their count.
    //
    iColumn = supAddLVColumnsFromArray(
        CmOptDlgContext.ListView,
        columnDataList,
        RTL_NUMBER_OF(columnDataList));

    CmOptDlgContext.lvColumnCount = iColumn;

    bIoDriverLoaded = kdIoDriverLoaded();
    CmOptDlgContext.Reserved = bIoDriverLoaded;

    if (bIoDriverLoaded) {
        supAddListViewColumn(CmOptDlgContext.ListView,
            iColumn,
            iColumn,
            iColumn,
            I_IMAGENONE,
            LVCFMT_CENTER | LVCFMT_BITMAP_ON_RIGHT,
            TEXT("Value (Memory)"), 80);

        CmOptDlgContext.lvColumnCount += 1;
        iColumn += 1;
    }

    if (g_NtBuildNumber >= NT_WIN10_REDSTONE4) {
        supAddListViewColumn(CmOptDlgContext.ListView,
            iColumn,
            iColumn,
            iColumn,
            I_IMAGENONE,
            LVCFMT_CENTER | LVCFMT_BITMAP_ON_RIGHT,
            TEXT("Flags"), 80);

        CmOptDlgContext.lvColumnCount += 1;
    }

    SetWindowText(hwndDlg, TEXT("CmControlVector (Relative to: \\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control)"));

    CmOptDlgListOptions(&CmOptDlgContext);

    SendMessage(hwndDlg, WM_SIZE, 0, 0);
    SetFocus(CmOptDlgContext.ListView);

    supCenterWindowSpecifyParent(hwndDlg, g_hwndMain);
}

/*
* CmOptDlgDialogProc
*
* Purpose:
*
* CmControlVector Dialog window procedure.
*
*/
INT_PTR CALLBACK CmOptDlgDialogProc(
    _In_  HWND hwndDlg,
    _In_  UINT uMsg,
    _In_  WPARAM wParam,
    _In_  LPARAM lParam
)
{
    if (uMsg == g_WinObj.SettingsChangeMessage) {
        extrasHandleSettingsChange(&CmOptDlgContext);
        return TRUE;
    }

    switch (uMsg) {

    case WM_SIZE:
        extrasSimpleListResize(hwndDlg);
        break;

    case WM_INITDIALOG:
        CmOptDlgOnInit(hwndDlg);
        break;

    case WM_DESTROY:
        CmOptDlgContext.hwndDlg = NULL;
        PostQuitMessage(0);
        break;

    case WM_CLOSE:
        extrasRemoveDlgIcon(&CmOptDlgContext);
        DestroyWindow(hwndDlg);
        return TRUE;

    case WM_COMMAND:
        CmOptDlgHandleWMCommand(hwndDlg, wParam, lParam);
        break;

    case WM_GETMINMAXINFO:
        if (lParam) {
            supSetMinMaxTrackSize((PMINMAXINFO)lParam,
                CMOPTDLG_TRACKSIZE_MIN_X,
                CMOPTDLG_TRACKSIZE_MIN_Y,
                TRUE);
        }
        break;

    case WM_NOTIFY:
        return (INT_PTR)CmOptDlgHandleNotify(
            (LPNMLISTVIEW)lParam,
            &CmOptDlgContext);

    case WM_CONTEXTMENU:
        supHandleContextMenuMsgForListView(hwndDlg,
            wParam,
            lParam,
            CmOptDlgContext.ListView,
            (pfnPopupMenuHandler)CmOptDlgHandlePopupMenu,
            &CmOptDlgContext);
        break;
    }

    return FALSE;
}

/*
* extrasCmOptDialogWorkerThread
*
* Purpose:
*
* CmControlVector Dialog thread.
*
*/
DWORD extrasCmOptDialogWorkerThread(
    _In_ PVOID Parameter
)
{
    BOOL bResult;
    MSG message;
    HWND hwndDlg;

    UNREFERENCED_PARAMETER(Parameter);

    hwndDlg = CreateDialogParam(
        g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_EXTRASLIST),
        0,
        &CmOptDlgDialogProc,
        0);

    supSetFastEvent(&CmOptInitializedEvent);

    if (hwndDlg) {

        do {

            bResult = GetMessage(&message, NULL, 0, 0);
            if (bResult == -1)
                break;

            if (!IsDialogMessage(hwndDlg, &message)) {
                TranslateMessage(&message);
                DispatchMessage(&message);
            }

        } while (bResult != 0);
    }

    supResetFastEvent(&CmOptInitializedEvent);
    supCloseHandleAtomic(&CmOptThreadHandle);

    return 0;
}

/*
* extrasCreateCmOptDialog
*
* Purpose:
*
* Create and initialize CmControlVector Dialog.
*
*/
VOID extrasCreateCmOptDialog(
    VOID
)
{
    if (!CmOptThreadHandle) {
        RtlSecureZeroMemory(&CmOptDlgContext, sizeof(EXTRASCONTEXT));
        CmOptThreadHandle = supCreateDialogWorkerThread(extrasCmOptDialogWorkerThread, NULL, 0);
        if (CmOptThreadHandle == NULL) {
            return;
        }
        supWaitForFastEvent(&CmOptInitializedEvent, NULL);
    }
    else {
        supRestoreDialogWindow(CmOptDlgContext.hwndDlg);
    }
}
