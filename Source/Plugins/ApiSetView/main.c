/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       MAIN.H
*
*  VERSION:     1.01
*
*  DATE:        15 Nov 2019
*
*  WinObjEx64 ApiSetView plugin.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

//
// Plugin entry.
//
WINOBJEX_PLUGIN *g_Plugin;

HINSTANCE g_ThisDLL;
BOOL g_PluginQuit = FALSE;

GUI_CONTEXT g_ctx;

/*
* OpenDialogExecute
*
* Purpose:
*
* Display OpenDialog
*
*/
BOOL OpenDialogExecute(
    _In_ HWND OwnerWindow,
    _Inout_ LPWSTR OpenFileName,
    _In_ LPWSTR lpDialogFilter
)
{
    OPENFILENAME tag1;

    RtlSecureZeroMemory(&tag1, sizeof(OPENFILENAME));

    tag1.lStructSize = sizeof(OPENFILENAME);
    tag1.hwndOwner = OwnerWindow;
    tag1.lpstrFilter = lpDialogFilter;
    tag1.lpstrFile = OpenFileName;
    tag1.nMaxFile = MAX_PATH;
    tag1.lpstrInitialDir = NULL;
    tag1.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    return GetOpenFileName(&tag1);
}

/*
* TreeView_FindLabel
*
* Purpose:
*
* Find treelist entry by label.
*
*/
HTREEITEM TreeView_FindLabel(
    _In_ HWND hwnd,
    _In_ HTREEITEM hItemParent,
    _In_ LPCWSTR pszLabel)
{
    TVITEMEX tvi;
    HTREEITEM hChildSearch;
    WCHAR wchLabel[MAX_PATH];

    for (tvi.hItem = TreeView_GetChild(hwnd, hItemParent);
        tvi.hItem;
        tvi.hItem = TreeView_GetNextSibling(hwnd, tvi.hItem))
    {
        tvi.mask = TVIF_TEXT | TVIF_CHILDREN;
        tvi.pszText = wchLabel;
        tvi.cchTextMax = MAX_PATH;
        if (TreeList_GetTreeItem(hwnd, &tvi, NULL)) {
            if (_strcmpi(tvi.pszText, pszLabel) == 0)
                return tvi.hItem;

            if (tvi.cChildren) {
                hChildSearch = TreeView_FindLabel(hwnd, tvi.hItem, pszLabel);
                if (hChildSearch)
                    return hChildSearch;
            }
        }
    }
    return 0;
}

/*
* HandleSearchSchema
*
* Purpose:
*
* Search in treelist.
*
*/
VOID HandleSearchSchema(
    _In_ HWND hwndDlg)
{
    HTREEITEM hItem;
    WCHAR szSchemaName[MAX_PATH * 2];

    RtlSecureZeroMemory(szSchemaName, sizeof(szSchemaName));

    SendDlgItemMessage(
        hwndDlg,
        IDC_SEARCH_EDIT,
        WM_GETTEXT,
        (WPARAM)MAX_PATH,
        (LPARAM)&szSchemaName);

    hItem = TreeView_FindLabel(
        g_ctx.TreeList,
        TreeView_GetRoot(g_ctx.TreeList),
        szSchemaName);

    if (hItem) {
        TreeList_EnsureVisible(g_ctx.TreeList, hItem);
        TreeList_Expand(g_ctx.TreeList, hItem, TVE_EXPAND);
        SetFocus(g_ctx.TreeList);
    }
}

/*
* HandleWMNotify
*
* Purpose:
*
* Main window WM_NOTIFY handler.
*
*/
VOID HandleWMNotify(
    _In_ HWND   hwndDlg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    TL_SUBITEMS_FIXED *subitems;
    LPNMHDR hdr = (LPNMHDR)lParam;

    UNREFERENCED_PARAMETER(wParam);

    HWND TreeList = (HWND)TreeList_GetTreeControlWindow(g_ctx.TreeList);

    TVITEMEX tvi;
    WCHAR szBuffer[MAX_PATH + 1];

    if (hdr->hwndFrom == TreeList) {
        switch (hdr->code) {
        case TVN_ITEMEXPANDED:
        case TVN_SELCHANGED:
            RtlSecureZeroMemory(&tvi, sizeof(tvi));
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

            tvi.mask = TVIF_TEXT;
            tvi.pszText = szBuffer;
            tvi.hItem = TreeList_GetSelection(g_ctx.TreeList);
            tvi.cchTextMax = MAX_PATH;
            if (TreeList_GetTreeItem(g_ctx.TreeList, &tvi, &subitems)) {
                SendDlgItemMessage(
                    hwndDlg,
                    IDC_ENTRY_EDIT,
                    WM_SETTEXT,
                    (WPARAM)0,
                    (LPARAM)&szBuffer);
            }

            break;
        default:
            break;
        }
    }
}

/*
* CenterWindow
*
* Purpose:
*
* Centers given window relative to desktop window.
*
*/
VOID CenterWindow(
    _In_ HWND hwnd
)
{
    RECT rc, rcDlg, rcOwner;
    HWND hwndParent = GetDesktopWindow();

    if (hwndParent) {
        GetWindowRect(hwndParent, &rcOwner);
        GetWindowRect(hwnd, &rcDlg);
        CopyRect(&rc, &rcOwner);
        OffsetRect(&rcDlg, -rcDlg.left, -rcDlg.top);
        OffsetRect(&rc, -rc.left, -rc.top);
        OffsetRect(&rc, -rcDlg.right, -rcDlg.bottom);

        //
        // Center window
        //
        SetWindowPos(hwnd,
            HWND_TOP,
            rcOwner.left + (rc.right / 2),
            rcOwner.top + (rc.bottom / 2),
            0, 0,
            SWP_NOSIZE);
    }
}

/*
* InitTreeList
*
* Purpose:
*
* Intialize TreeList control.
*
*/
BOOL InitTreeList(
    _In_ HWND hwndParent,
    _Out_ HWND *pTreeListHwnd
)
{
    HWND     TreeList;
    HDITEM   hdritem;
    RECT     rc;

    UINT uDpi;
    INT dpiScaledX, dpiScaledY, iScaledWidth, iScaledHeight, iScaleSubX, iScaleSubY;

    if (pTreeListHwnd == NULL) {
        return FALSE;
    }

    uDpi = g_ctx.ParamBlock.uiGetDPIValue(NULL);
    dpiScaledX = MulDiv(10, uDpi, DefaultSystemDpi);
    dpiScaledY = dpiScaledX;

    GetWindowRect(hwndParent, &rc);

    iScaleSubX = MulDiv(24, uDpi, DefaultSystemDpi);
    iScaleSubY = MulDiv(200, uDpi, DefaultSystemDpi);
    iScaledWidth = (rc.right - rc.left) - dpiScaledX - iScaleSubX;
    iScaledHeight = (rc.bottom - rc.top) - dpiScaledY - iScaleSubY;

    TreeList = CreateWindowEx(WS_EX_CLIENTEDGE, WC_TREELIST, NULL,
        WS_VISIBLE | WS_CHILD | WS_TABSTOP | TLSTYLE_COLAUTOEXPAND | TLSTYLE_LINKLINES, 
        dpiScaledX, dpiScaledY,
        iScaledWidth, iScaledHeight, hwndParent, NULL, NULL, NULL);

    if (TreeList == NULL) {
        *pTreeListHwnd = NULL;
        return FALSE;
    }

    *pTreeListHwnd = TreeList;

    RtlSecureZeroMemory(&hdritem, sizeof(hdritem));
    hdritem.mask = HDI_FORMAT | HDI_TEXT | HDI_WIDTH;
    hdritem.fmt = HDF_LEFT | HDF_BITMAP_ON_RIGHT | HDF_STRING;
    hdritem.cxy = 300;
    hdritem.pszText = TEXT("Namespace");
    TreeList_InsertHeaderItem(TreeList, 0, &hdritem);
    hdritem.cxy = 130;
    hdritem.pszText = TEXT("Alias");
    TreeList_InsertHeaderItem(TreeList, 1, &hdritem);
    hdritem.cxy = 200;
    hdritem.pszText = TEXT("Flags");
    TreeList_InsertHeaderItem(TreeList, 2, &hdritem);

    return TRUE;
}

/*
* AsWindowDialogProc
*
* Purpose:
*
* Main plugin window procedure.
*
*/
INT_PTR CALLBACK AsWindowDialogProc(
    _In_ HWND   hwndDlg,
    _In_ UINT   uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    HANDLE hImage;
    HTREEITEM hRoot;
    WCHAR szOpenFileName[MAX_PATH + 1];

    switch (uMsg) {

    case WM_INITDIALOG:

        g_ctx.MainWindow = hwndDlg;

        hImage = LoadImage(
            g_ctx.ParamBlock.hInstance,
            MAKEINTRESOURCE(WINOBJEX64_ICON_MAIN),
            IMAGE_ICON,
            0,
            0,
            LR_SHARED);

        if (hImage) {
            SetClassLongPtr(hwndDlg, GCLP_HICON, (LONG_PTR)hImage);
            DestroyIcon(hImage);
        }

        if (InitTreeList(hwndDlg, &g_ctx.TreeList)) {
            ListApiSetFromFile(NULL);
        }
        else {
            MessageBox(g_ctx.MainWindow,
                TEXT("ApiSetView: Could not initialize treelist window"),
                NULL,
                MB_ICONERROR);
        }

        break;

    case WM_SHOWWINDOW:
        if (wParam) {
            CenterWindow(hwndDlg);
            SendDlgItemMessage(hwndDlg, IDC_SEARCH_EDIT, EM_LIMITTEXT, MAX_PATH, 0);
            hRoot = TreeList_GetRoot(g_ctx.TreeList);
            TreeList_EnsureVisible(g_ctx.TreeList, hRoot);
            SetFocus(g_ctx.TreeList);
        }
        break;

    case WM_NOTIFY:
        HandleWMNotify(
            hwndDlg,
            wParam,
            lParam);
        break;

    case WM_COMMAND:

        switch (LOWORD(wParam)) {
        case IDC_SEARCH_BUTTON:
            HandleSearchSchema(hwndDlg);
            break;

        case IDC_BROWSE_BUTTON:
            RtlSecureZeroMemory(szOpenFileName, sizeof(szOpenFileName));
            if (OpenDialogExecute(hwndDlg,
                szOpenFileName,
                TEXT("All files\0*.*\0\0")))
            {
                ListApiSetFromFile(szOpenFileName);
            }
            break;

        case IDOK:
        case IDCANCEL:
            g_PluginQuit = TRUE;
            PostQuitMessage(0);
            return EndDialog(hwndDlg, S_OK);
            break;
        default:
            break;
        }

    default:
        break;
    }
    return 0;
}

/*
* PluginFreeGlobalResources
*
* Purpose:
*
* Plugin resources deallocation routine.
*
*/
VOID PluginFreeGlobalResources()
{
    if (g_ctx.PluginHeap) {
        HeapDestroy(g_ctx.PluginHeap);
        g_ctx.PluginHeap = NULL;
    }

    g_Plugin->StateChangeCallback(g_Plugin, PluginStopped, NULL);
}

/*
* PluginThread
*
* Purpose:
*
* Plugin payload thread.
*
*/
DWORD WINAPI PluginThread(
    _In_ PVOID Parameter
)
{
    UNREFERENCED_PARAMETER(Parameter);

    INITCOMMONCONTROLSEX icex;

    BOOL rv;
    MSG msg1;

    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES;
    InitCommonControlsEx(&icex);

    DialogBoxParam(
        g_ThisDLL,
        MAKEINTRESOURCE(IDD_ASDIALOG),
        NULL,
        AsWindowDialogProc,
        0);

    do {
        rv = GetMessage(&msg1, NULL, 0, 0);

        if (rv == -1)
            break;

        TranslateMessage(&msg1);
        DispatchMessage(&msg1);

    } while ((rv != 0) || (g_PluginQuit == FALSE));

    PluginFreeGlobalResources();

    ExitThread(0);
}

/*
* StartPlugin
*
* Purpose:
*
* Run actual plugin code in dedicated thread.
*
*/
NTSTATUS CALLBACK StartPlugin(
    _In_ PWINOBJEX_PARAM_BLOCK ParamBlock
)
{
    DWORD ThreadId;
    NTSTATUS Status;
    WINOBJEX_PLUGIN_STATE State = PluginInitialization;

    RtlSecureZeroMemory(&g_ctx, sizeof(g_ctx));

    g_ctx.PluginHeap = HeapCreate(0, 0, 0);
    if (g_ctx.PluginHeap == NULL)
        return STATUS_MEMORY_NOT_ALLOCATED;

    HeapSetInformation(g_ctx.PluginHeap, HeapEnableTerminationOnCorruption, NULL, 0);

    RtlCopyMemory(&g_ctx.ParamBlock, ParamBlock, sizeof(WINOBJEX_PARAM_BLOCK));

    g_ctx.WorkerThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PluginThread, (PVOID)NULL, 0, &ThreadId);
    if (g_ctx.WorkerThread) {
        Status = STATUS_SUCCESS;
    }
    else {
        Status = STATUS_UNSUCCESSFUL;
    }

    if (NT_SUCCESS(Status))
        State = PluginRunning;
    else
        State = PluginError;

    g_Plugin->StateChangeCallback(g_Plugin, State, NULL);

    return Status;
}

/*
* StopPlugin
*
* Purpose:
*
* Stop plugin execution.
*
*/
void CALLBACK StopPlugin(
    VOID
)
{
    if (g_ctx.WorkerThread) {
        InterlockedExchange((PLONG)&g_PluginQuit, 1);
        if (WaitForSingleObject(g_ctx.WorkerThread, 1000) == WAIT_TIMEOUT) {
            TerminateThread(g_ctx.WorkerThread, 0);
        }
        CloseHandle(g_ctx.WorkerThread);
        g_ctx.WorkerThread = NULL;
        g_Plugin->StateChangeCallback(g_Plugin, PluginStopped, NULL);
    }
}

/*
* PluginInit
*
* Purpose:
*
* Initialize plugin information for WinObjEx64.
*
*/
BOOLEAN CALLBACK PluginInit(
    _Out_ PWINOBJEX_PLUGIN PluginData
)
{
    __try {
        //
        // Set plugin name to be displayed in WinObjEx64 UI.
        //
        StringCbCopy(PluginData->Description, sizeof(PluginData->Description), TEXT("ApiSetView"));

        //
        // Setup start/stop plugin callbacks.
        //
        PluginData->StartPlugin = (pfnStartPlugin)&StartPlugin;
        PluginData->StopPlugin = (pfnStopPlugin)&StopPlugin;

        //
        // Setup permissions.
        //
        PluginData->NeedAdmin = FALSE;
        PluginData->SupportWine = FALSE;
        PluginData->NeedDriver = FALSE;

        PluginData->MajorVersion = 1;
        PluginData->MinorVersion = 0;
        g_Plugin = PluginData;

        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("PluginInit exception thrown %lx\r\n", GetExceptionCode());
        return FALSE;
    }
}

/*
* DllMain
*
* Purpose:
*
* Dummy dll entrypoint.
*
*/
BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD     fdwReason,
    _In_ LPVOID    lpvReserved
)
{
    UNREFERENCED_PARAMETER(lpvReserved);

    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_ThisDLL = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
    }
    return TRUE;
}
