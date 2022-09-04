/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       EXTRASCMOPT.C
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
    _In_ EXTRASCONTEXT* Context,
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
            Context->ListView,
            iItem,
            COLUMN_CMOPTLIST_BUFFER,
            szBuffer,
            MAX_TEXT_CONVERSION_ULONG64);

        variableAddress = hextou64(&szBuffer[2]);
        if (variableAddress < g_kdctx.SystemRangeStart)
            break;

        szBuffer[0] = 0;
        supGetItemText2(
            Context->ListView,
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
        if (!supSaveDialogExecute(Context->hwndDlg, szBuffer, TEXT("All files\0*.*\0\0"))) {
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
            Context->hwndDlg,
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
    EXTRASCONTEXT* pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);

    switch (GET_WM_COMMAND_ID(wParam, lParam)) {

    case ID_OBJECT_COPY:

        if (pDlgContext) {

            supListViewCopyItemValueToClipboard(pDlgContext->ListView,
                pDlgContext->lvItemHit,
                pDlgContext->lvColumnHit);

        }

        break;

    case ID_CMOPTLIST_SAVE:

        if (pDlgContext) {

            supListViewExportToFile(
                TEXT("CmControlVector.csv"),
                hwndDlg,
                pDlgContext->ListView);
        }
        break;

    case ID_CMOPTLIST_DUMP:

        if (pDlgContext) {

            CmOptDlgDumpValueToFile(pDlgContext,
                pDlgContext->lvItemHit);

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

    supListViewEnableRedraw(hwndList, FALSE);

    while (CmControlVector.Version.v1->KeyPath != NULL) {
        CmpOptDlgAddEntry(hwndList, CmControlVector.Ref, size, (Context->Reserved != 0));
        CmControlVector.Ref += size;
    }

    ListView_SortItemsEx(hwndList,
        &CmOptDlgCompareFunc,
        (LPARAM)Context);

    supListViewEnableRedraw(hwndList, TRUE);

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
    _In_ HWND hwndDlg,
    _In_ LPARAM lParam
)
{
    EXTRASCONTEXT* pDlgContext = (EXTRASCONTEXT*)lParam;
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

    SetProp(hwndDlg, T_DLGCONTEXT, (HANDLE)pDlgContext);

    pDlgContext->hwndDlg = hwndDlg;
    pDlgContext->lvItemHit = -1;
    pDlgContext->lvColumnHit = -1;

    extrasSetDlgIcon(pDlgContext);

    pDlgContext->StatusBar = GetDlgItem(hwndDlg, ID_EXTRASLIST_STATUSBAR);
    pDlgContext->ListView = GetDlgItem(hwndDlg, ID_EXTRASLIST);
    pDlgContext->lvColumnHit = -1;
    pDlgContext->lvItemHit = -1;

    //
    // Set listview imagelist, style flags and theme.
    //
    supSetListViewSettings(pDlgContext->ListView,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP,
        FALSE,
        TRUE,
        g_ListViewImages,
        LVSIL_SMALL);

    //
    // And columns and remember their count.
    //
    iColumn = supAddLVColumnsFromArray(
        pDlgContext->ListView,
        columnDataList,
        RTL_NUMBER_OF(columnDataList));

    pDlgContext->lvColumnCount = iColumn;

    bIoDriverLoaded = kdIoDriverLoaded();
    pDlgContext->Reserved = bIoDriverLoaded;

    if (bIoDriverLoaded) {
        supAddListViewColumn(pDlgContext->ListView,
            iColumn,
            iColumn,
            iColumn,
            I_IMAGENONE,
            LVCFMT_CENTER | LVCFMT_BITMAP_ON_RIGHT,
            TEXT("Value (Memory)"), 80);

        pDlgContext->lvColumnCount += 1;
        iColumn += 1;
    }

    if (g_NtBuildNumber >= NT_WIN10_REDSTONE4) {
        supAddListViewColumn(pDlgContext->ListView,
            iColumn,
            iColumn,
            iColumn,
            I_IMAGENONE,
            LVCFMT_CENTER | LVCFMT_BITMAP_ON_RIGHT,
            TEXT("Flags"), 80);

        pDlgContext->lvColumnCount += 1;
    }

    SetWindowText(hwndDlg, TEXT("CmControlVector (Relative to: \\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control)"));

    CmOptDlgListOptions(pDlgContext);

    SendMessage(hwndDlg, WM_SIZE, 0, 0);
    SetFocus(pDlgContext->ListView);

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
    EXTRASCONTEXT* pDlgContext;

    if (uMsg == g_WinObj.SettingsChangeMessage) {
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            extrasHandleSettingsChange(pDlgContext);
        }
        return TRUE;
    }

    switch (uMsg) {

    case WM_SIZE:
        extrasSimpleListResize(hwndDlg);
        break;

    case WM_INITDIALOG:
        CmOptDlgOnInit(hwndDlg, lParam);
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    case WM_CLOSE:
        pDlgContext = (EXTRASCONTEXT*)RemoveProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            extrasRemoveDlgIcon(pDlgContext);
            supHeapFree(pDlgContext);
        }
        return DestroyWindow(hwndDlg);

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

        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            return (INT_PTR)CmOptDlgHandleNotify(
                (LPNMLISTVIEW)lParam,
                pDlgContext);
        }
        break;

    case WM_CONTEXTMENU:

        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            supHandleContextMenuMsgForListView(hwndDlg,
                wParam,
                lParam,
                pDlgContext->ListView,
                (pfnPopupMenuHandler)CmOptDlgHandlePopupMenu,
                pDlgContext);
        }
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
    EXTRASCONTEXT* pDlgContext = (EXTRASCONTEXT*)Parameter;

    hwndDlg = CreateDialogParam(
        g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_EXTRASLIST),
        0,
        &CmOptDlgDialogProc,
        (LPARAM)pDlgContext);

    supSetFastEvent(&CmOptInitializedEvent);

    do {

        bResult = GetMessage(&message, NULL, 0, 0);
        if (bResult == -1)
            break;

        if (!IsDialogMessage(hwndDlg, &message)) {
            TranslateMessage(&message);
            DispatchMessage(&message);
        }

    } while (bResult != 0);

    supResetFastEvent(&CmOptInitializedEvent);

    if (CmOptThreadHandle) {
        NtClose(CmOptThreadHandle);
        CmOptThreadHandle = NULL;
    }

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
    EXTRASCONTEXT* pDlgContext;

    if (!CmOptThreadHandle) {

        pDlgContext = (EXTRASCONTEXT*)supHeapAlloc(sizeof(EXTRASCONTEXT));
        if (pDlgContext) {

            pDlgContext->tlSubItemHit = -1;
            CmOptThreadHandle = supCreateDialogWorkerThread(extrasCmOptDialogWorkerThread, pDlgContext , 0);
            supWaitForFastEvent(&CmOptInitializedEvent, NULL);

        }

    }
}
