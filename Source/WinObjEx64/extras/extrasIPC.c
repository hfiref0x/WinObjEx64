/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2019
*
*  TITLE:       EXTRASIPC.C
*
*  VERSION:     1.82
*
*  DATE:        13 Nov 2019
*
*  IPC supported: Pipes, Mailslots
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "extras.h"
#include "extrasIPC.h"
#include "propDlg.h"
#include "propSecurity.h"

//mailslot root
#define DEVICE_MAILSLOT          L"\\Device\\Mailslot\\"
#define DEVICE_MAILSLOT_LENGTH   sizeof(DEVICE_MAILSLOT) - sizeof(WCHAR)

//named pipes root
#define DEVICE_NAMED_PIPE        L"\\Device\\NamedPipe\\"
#define DEVICE_NAMED_PIPE_LENGTH sizeof(DEVICE_NAMED_PIPE) - sizeof(WCHAR)

EXTRASCONTEXT IpcDlgContext[IpcMaxMode];

//maximum number of possible pages
#define EXTRAS_IPC_MAX_PAGE 2
HPROPSHEETPAGE IpcPages[EXTRAS_IPC_MAX_PAGE];//object, security

/*
* IpcDisplayError
*
* Purpose:
*
* Display last Win32 error.
*
*/
VOID IpcDisplayError(
    _In_ HWND hwndDlg,
    _In_ IPC_DIALOG_MODE DialogMode
)
{
    DWORD dwLastError;
    WCHAR szBuffer[MAX_PATH * 2];

    dwLastError = GetLastError();
    ShowWindow(GetDlgItem(hwndDlg, ID_PIPE_QUERYFAIL), SW_SHOW);

    RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));

    switch (DialogMode) {
    case IpcModeMailSlots:
        _strcpy(szBuffer, TEXT("Cannot open mailslot because: "));
        break;
    case IpcModeNamedPipes:
    default:
        _strcpy(szBuffer, TEXT("Cannot open pipe because: "));
        break;
    }

    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, dwLastError,
        0, _strend(szBuffer), MAX_PATH, NULL);
    SetDlgItemText(hwndDlg, ID_PIPE_QUERYFAIL, szBuffer);
}

/*
* IpcCreateObjectPathWithName
*
* Purpose:
*
* Create complete object name including directory.
* Caller responsible for cleanup with supHeapFree after use.
*
*/
LPWSTR IpcCreateObjectPathWithName(
    _In_ LPWSTR lpObjectName,
    _In_ IPC_DIALOG_MODE Mode
)
{
    LPWSTR lpFullName = NULL, lpRootDirectory = NULL;
    SIZE_T sz;

    if (lpObjectName == NULL) {
        return NULL;
    }

    sz = (1 + _strlen(lpObjectName)) * sizeof(WCHAR);

    switch (Mode) {
    case IpcModeNamedPipes:
        sz += DEVICE_NAMED_PIPE_LENGTH;
        lpRootDirectory = DEVICE_NAMED_PIPE;
        break;
    case IpcModeMailSlots:
        sz += DEVICE_MAILSLOT_LENGTH;
        lpRootDirectory = DEVICE_MAILSLOT;
        break;
    default:
        break;
    }
    if (lpRootDirectory) {
        lpFullName = (LPWSTR)supHeapAlloc(sz);
        if (lpFullName == NULL) {
            return NULL;
        }
        _strcpy(lpFullName, lpRootDirectory);
        _strcat(lpFullName, lpObjectName);
    }
    return lpFullName;
}

/*
* IpcOpenObjectMethod
*
* Purpose:
*
* Used by Security Editor to access object by name.
*
*/
BOOL CALLBACK IpcOpenObjectMethod(
    _In_	PROP_OBJECT_INFO *Context,
    _Inout_ PHANDLE	phObject,
    _In_	ACCESS_MASK	DesiredAccess
)
{
    BOOL                bResult = FALSE;
    HANDLE              hObject;
    NTSTATUS            status;
    OBJECT_ATTRIBUTES   obja;
    UNICODE_STRING      uStr;
    IO_STATUS_BLOCK     iost;

    if (
        (Context == NULL) ||
        (phObject == NULL)
        )
    {
        return bResult;
    }
    *phObject = NULL;

    RtlInitUnicodeString(&uStr, Context->lpCurrentObjectPath);
    InitializeObjectAttributes(&obja, &uStr, OBJ_CASE_INSENSITIVE, NULL, NULL);
    hObject = NULL;

    status = NtOpenFile(&hObject, DesiredAccess, &obja, &iost,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_NON_DIRECTORY_FILE);

    if (NT_SUCCESS(status)) {
        *phObject = hObject;
    }
    SetLastError(RtlNtStatusToDosError(status));
    bResult = (NT_SUCCESS(status) && (hObject != NULL));
    return bResult;
}

/*
* IpcMailslotQueryInfo
*
* Purpose:
*
* Query basic info about mailslot.
*
*/
VOID IpcMailslotQueryInfo(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    HANDLE          hMailslot;
    NTSTATUS        status;
    WCHAR           szBuffer[MAX_PATH];
    IO_STATUS_BLOCK iost;

    FILE_MAILSLOT_QUERY_INFORMATION fmqi;

    //validate context
    if (Context == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        IpcDisplayError(hwndDlg, IpcModeMailSlots);
        return;
    }
    if (
        (Context->lpObjectName == NULL) ||
        (Context->lpCurrentObjectPath == NULL)
        )
    {
        SetLastError(ERROR_OBJECT_NOT_FOUND);
        IpcDisplayError(hwndDlg, IpcModeMailSlots);
        return;
    }

    hMailslot = NULL;
    if (!IpcOpenObjectMethod(Context, &hMailslot, GENERIC_READ)) {
        //on error display last win32 error
        IpcDisplayError(hwndDlg, IpcModeMailSlots);
        return;
    }

    SetDlgItemText(hwndDlg, ID_MAILSLOT_FULLPATH, Context->lpCurrentObjectPath);

    RtlSecureZeroMemory(&fmqi, sizeof(fmqi));
    status = NtQueryInformationFile(hMailslot, &iost, &fmqi, sizeof(fmqi), FileMailslotQueryInformation);
    if (NT_SUCCESS(status)) {
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));

        //mailslot quota
        ultostr(fmqi.MailslotQuota, szBuffer);
        SetDlgItemText(hwndDlg, ID_MAILSLOT_QUOTA, szBuffer);

        //messages available
        ultostr(fmqi.MessagesAvailable, szBuffer);
        SetDlgItemText(hwndDlg, ID_MAILSLOT_MSGAVAILABLE, szBuffer);

        //next message
        ultohex(fmqi.NextMessageSize, szBuffer);
        SetDlgItemText(hwndDlg, ID_MAILSLOT_NEXTMSGSZ, szBuffer);

        //maximum message size
        ultostr(fmqi.MaximumMessageSize, szBuffer);
        SetDlgItemText(hwndDlg, ID_MAILSLOT_MAXMESSAGESZ, szBuffer);

        //read timeout
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        ultohex(fmqi.ReadTimeout.LowPart, szBuffer);
        _strcat(szBuffer, L":");
        ultohex(fmqi.ReadTimeout.HighPart, _strend(szBuffer));
        SetDlgItemText(hwndDlg, ID_MAILSLOT_READTIMEOUT, szBuffer);
    }
    NtClose(hMailslot);
}

/*
* IpcPipeQueryInfo
*
* Purpose:
*
* Query basic info about pipe.
*
*/
VOID IpcPipeQueryInfo(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    LPWSTR                      lpType;
    HANDLE                      hPipe;
    NTSTATUS                    status;
    WCHAR                       szBuffer[MAX_PATH];
    IO_STATUS_BLOCK             iost;
    FILE_PIPE_LOCAL_INFORMATION fpli;

    //validate context
    if (Context == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        IpcDisplayError(hwndDlg, IpcModeNamedPipes);
        return;
    }
    if (
        (Context->lpObjectName == NULL) ||
        (Context->lpCurrentObjectPath == NULL)
        )
    {
        SetLastError(ERROR_OBJECT_NOT_FOUND);
        IpcDisplayError(hwndDlg, IpcModeNamedPipes);
        return;
    }

    SetDlgItemText(hwndDlg, ID_PIPE_FULLPATH, Context->lpCurrentObjectPath);

    //open pipe
    hPipe = NULL;
    if (!IpcOpenObjectMethod(Context, &hPipe, GENERIC_READ)) {
        IpcDisplayError(hwndDlg, IpcModeNamedPipes);
        return;
    }

    RtlSecureZeroMemory(&fpli, sizeof(fpli));
    status = NtQueryInformationFile(hPipe, &iost, &fpli, sizeof(fpli), FilePipeLocalInformation);
    if (NT_SUCCESS(status)) {

        //Type
        lpType = TEXT("?");
        switch (fpli.NamedPipeType) {
        case FILE_PIPE_BYTE_STREAM_TYPE:
            lpType = TEXT("Byte stream");
            break;
        case FILE_PIPE_MESSAGE_TYPE:
            lpType = TEXT("Message");
            break;
        }
        SetDlgItemText(hwndDlg, ID_PIPE_TYPEMODE, lpType);

        //AccessMode
        lpType = TEXT("?");
        switch (fpli.NamedPipeConfiguration) {
        case FILE_PIPE_INBOUND:
            lpType = TEXT("Inbound");
            break;
        case FILE_PIPE_OUTBOUND:
            lpType = TEXT("Outbound");
            break;
        case FILE_PIPE_FULL_DUPLEX:
            lpType = TEXT("Duplex");
            break;
        }
        SetDlgItemText(hwndDlg, ID_PIPE_ACCESSMODE, lpType);

        //CurrentInstances
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        ultostr(fpli.CurrentInstances, szBuffer);
        SetDlgItemText(hwndDlg, ID_PIPE_CURINSTANCES, szBuffer);

        //MaximumInstances
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        if (fpli.MaximumInstances == MAXDWORD) {
            _strcpy(szBuffer, TEXT("Unlimited"));
        }
        else {
            ultostr(fpli.MaximumInstances, szBuffer);
        }
        SetDlgItemText(hwndDlg, ID_PIPE_MAXINSTANCES, szBuffer);

        //InboundQuota
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        ultostr(fpli.InboundQuota, szBuffer);
        SetDlgItemText(hwndDlg, ID_PIPE_INBUFFER, szBuffer);

        //OutboundQuota
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        ultostr(fpli.OutboundQuota, szBuffer);
        SetDlgItemText(hwndDlg, ID_PIPE_OUTBUFFER, szBuffer);

        //WriteQuotaAvailable
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        ultostr(fpli.WriteQuotaAvailable, szBuffer);
        SetDlgItemText(hwndDlg, ID_PIPE_WRITEQUOTAAVAIL, szBuffer);
    }
    else {
        //show detail on query error
        SetLastError(RtlNtStatusToDosError(status));
        IpcDisplayError(hwndDlg, IpcModeNamedPipes);
    }
    NtClose(hPipe);
}

/*
* IpcTypeDialogProc
*
* Purpose:
*
* Object Properties Dialog Procedure
*
*/
INT_PTR CALLBACK IpcTypeDialogProc(
    _In_  HWND hwndDlg,
    _In_  UINT uMsg,
    _In_  WPARAM wParam,
    _In_  LPARAM lParam
)
{
    PROPSHEETPAGE    *pSheet = NULL;
    PROP_OBJECT_INFO *Context = NULL;
    HICON             hIcon;

    EXTRASCONTEXT *pDlgContext;

    switch (uMsg) {

    case WM_INITDIALOG:
        pSheet = (PROPSHEETPAGE *)lParam;
        if (pSheet) {
            SetProp(hwndDlg, T_PROPCONTEXT, (HANDLE)pSheet->lParam);
            Context = (PROP_OBJECT_INFO*)pSheet->lParam;
            if (Context) {
                pDlgContext = (EXTRASCONTEXT*)Context->Tag;
                if (pDlgContext) {

                    hIcon = ImageList_GetIcon(pDlgContext->ImageList,
                        0,
                        ILD_NORMAL | ILD_TRANSPARENT);
                    if (hIcon) {
                        SendMessage(GetDlgItem(hwndDlg, ID_OBJECT_ICON), STM_SETIMAGE, IMAGE_ICON, (LPARAM)hIcon);
                        pDlgContext->ObjectIcon = hIcon;
                    }

                }
            }
        }
        return 1;
        break;

    case WM_SHOWWINDOW:
        if (wParam) {
            Context = (PROP_OBJECT_INFO*)GetProp(hwndDlg, T_PROPCONTEXT);
            if (Context) {
                pDlgContext = (EXTRASCONTEXT*)Context->Tag;
                if (pDlgContext) {
                    switch (pDlgContext->DialogMode) {
                    case IpcModeMailSlots:
                        IpcMailslotQueryInfo(Context, hwndDlg);
                        break;
                    case IpcModeNamedPipes:
                        IpcPipeQueryInfo(Context, hwndDlg);
                        break;
                    default:
                        break;
                    }
                }
            }
        }
        return 1;
        break;

    case WM_DESTROY:
        Context = (PROP_OBJECT_INFO*)GetProp(hwndDlg, T_PROPCONTEXT);
        if (Context) {
            pDlgContext = (EXTRASCONTEXT*)Context->Tag;
            if (pDlgContext) {
                DestroyIcon(pDlgContext->ObjectIcon);
                pDlgContext->ObjectIcon = NULL;
            }
        }
        RemoveProp(hwndDlg, T_PROPCONTEXT);
        break;

    }
    return 0;
}

/*
* IpcDlgShowProperties
*
* Purpose:
*
* Show properties dialog for selected object.
* Because of Pipe special case we cannot use propCreateDialog.
*
*/
VOID IpcDlgShowProperties(
    _In_ INT iItem,
    _In_ EXTRASCONTEXT *pDlgContext
)
{
    INT                 nPages = 0;
    PROP_OBJECT_INFO   *Context;
    HPROPSHEETPAGE      SecurityPage = NULL;
    PROPSHEETPAGE       Page;
    PROPSHEETHEADER     PropHeader;
    WCHAR               szCaption[MAX_PATH];

    Context = propContextCreate(NULL, OBTYPE_NAME_FILE, NULL, NULL);
    if (Context == NULL) {
        return;
    }

    Context->lpObjectName = supGetItemText(pDlgContext->ListView, iItem, 0, NULL);
    Context->lpCurrentObjectPath = IpcCreateObjectPathWithName(Context->lpObjectName, 
        (IPC_DIALOG_MODE)pDlgContext->DialogMode);
    Context->Tag = (ULONG_PTR)pDlgContext;

    RtlSecureZeroMemory(&IpcPages, sizeof(IpcPages));
    //
    //Create object page
    //
    RtlSecureZeroMemory(&Page, sizeof(Page));
    Page.dwSize = sizeof(PROPSHEETPAGE);
    Page.dwFlags = PSP_DEFAULT | PSP_USETITLE;
    Page.hInstance = g_WinObj.hInstance;
    Page.pfnDlgProc = IpcTypeDialogProc;

    switch (pDlgContext->DialogMode) {
    case IpcModeMailSlots:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_MAILSLOT);
        Page.pszTitle = TEXT("Mailslot");
        break;
    case IpcModeNamedPipes:
    default:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_PIPE);
        Page.pszTitle = TEXT("Pipe");
        break;
    }
    Page.lParam = (LPARAM)Context;
    IpcPages[nPages++] = CreatePropertySheetPage(&Page);

    //
    // Disconnected clients cannot query security (see msfs!MsCommonQuerySecurityInfo).
    //
    if (pDlgContext->DialogMode != IpcModeMailSlots) {

        //
        //Create Security Dialog if available
        //
        SecurityPage = propSecurityCreatePage(
            Context,
            (POPENOBJECTMETHOD)&IpcOpenObjectMethod,
            NULL, //use default close method
            SI_EDIT_OWNER | SI_EDIT_PERMS | 
            SI_ADVANCED | SI_NO_ACL_PROTECT | SI_NO_TREE_APPLY |
            SI_PAGE_TITLE
        );
        if (SecurityPage != NULL) {
            IpcPages[nPages++] = SecurityPage;
        }
    }

    //
    //Create property sheet
    //
    _strcpy(szCaption, TEXT("Properties"));
    RtlSecureZeroMemory(&PropHeader, sizeof(PropHeader));
    PropHeader.dwSize = sizeof(PropHeader);
    PropHeader.phpage = IpcPages;
    PropHeader.nPages = nPages;
    PropHeader.dwFlags = PSH_DEFAULT | PSH_NOCONTEXTHELP;
    PropHeader.nStartPage = 0;
    PropHeader.hwndParent = pDlgContext->hwndDlg;
    PropHeader.hInstance = g_WinObj.hInstance;
    PropHeader.pszCaption = szCaption;

    PropertySheet(&PropHeader);
    propContextDestroy(Context);
}

/*
* IpcDlgCompareFunc
*
* Purpose:
*
* Ipc Dialog listview comparer function.
*
*/
INT CALLBACK IpcDlgCompareFunc(
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort //pointer to EXTRASCALLBACK
)
{
    LPWSTR lpItem1, lpItem2;
    INT    nResult = 0;

    EXTRASCONTEXT *pDlgContext;
    EXTRASCALLBACK *CallbackParam = (EXTRASCALLBACK*)lParamSort;

    if (CallbackParam == NULL)
        return 0;

    pDlgContext = &IpcDlgContext[CallbackParam->Value];

    lpItem1 = supGetItemText(pDlgContext->ListView, (INT)lParam1, (INT)CallbackParam->lParam, NULL);
    lpItem2 = supGetItemText(pDlgContext->ListView, (INT)lParam2, (INT)CallbackParam->lParam, NULL);

    if ((lpItem1 == NULL) && (lpItem2 == NULL)) {
        nResult = 0;
        goto Done;
    }

    if ((lpItem1 == NULL) && (lpItem2 != NULL)) {
        nResult = (pDlgContext->bInverseSort) ? 1 : -1;
        goto Done;
    }
    if ((lpItem2 == NULL) && (lpItem1 != NULL)) {
        nResult = (pDlgContext->bInverseSort) ? -1 : 1;
        goto Done;
    }

    if (pDlgContext->bInverseSort)
        nResult = _strcmpi(lpItem2, lpItem1);
    else
        nResult = _strcmpi(lpItem1, lpItem2);

Done:
    if (lpItem1) {
        supHeapFree(lpItem1);
    }
    if (lpItem2) {
        supHeapFree(lpItem2);
    }
    return nResult;
}

/*
* IpcDlgQueryInfo
*
* Purpose:
*
* List objects from device.
*
*/
VOID IpcDlgQueryInfo(
    _In_ LPWSTR lpObjectRoot,
    _In_ HWND ListView
)
{
    BOOLEAN                     bRestartScan;
    ULONG                       QuerySize;
    HANDLE                      hObject = NULL;
    FILE_DIRECTORY_INFORMATION *DirectoryInfo = NULL;
    NTSTATUS                    status;
    OBJECT_ATTRIBUTES           obja;
    UNICODE_STRING              uStr;
    IO_STATUS_BLOCK             iost;
    LVITEM                      lvitem;
    INT                         c;

    __try {

        RtlInitUnicodeString(&uStr, lpObjectRoot);
        InitializeObjectAttributes(&obja, &uStr, OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = NtOpenFile(&hObject, FILE_LIST_DIRECTORY, &obja, &iost,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0);
        if (!NT_SUCCESS(status) || (hObject == NULL))
            __leave;

        QuerySize = 0x1000;
        DirectoryInfo = (FILE_DIRECTORY_INFORMATION*)supHeapAlloc((SIZE_T)QuerySize);
        if (DirectoryInfo == NULL)
            __leave;

        c = 0;
        bRestartScan = TRUE;
        while (TRUE) {

            RtlSecureZeroMemory(&iost, sizeof(iost));

            status = NtQueryDirectoryFile(hObject, NULL, NULL, NULL, &iost,
                DirectoryInfo,
                QuerySize,
                FileDirectoryInformation,
                TRUE, //ReturnSingleEntry
                NULL,
                bRestartScan //RestartScan
            );

            if (
                (!NT_SUCCESS(status)) ||
                (!NT_SUCCESS(iost.Status)) ||
                (iost.Information == 0)
                )
            {
                break;
            }

            //Name
            RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
            lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
            lvitem.pszText = DirectoryInfo->FileName;
            lvitem.iItem = MAXINT;
            ListView_InsertItem(ListView, &lvitem);
            bRestartScan = FALSE;
            RtlSecureZeroMemory(DirectoryInfo, QuerySize);

            c++;
            if (c > 1000) {//its a trap
                break;
            }
        }
    }
    __finally {

        if (DirectoryInfo != NULL) {
            supHeapFree(DirectoryInfo);
        }

        if (hObject) {
            NtClose(hObject);
        }
    }
}

/*
* IpcDlgHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for dialog listview.
*
*/
VOID IpcDlgHandleNotify(
    _In_ LPARAM lParam,
    _In_ EXTRASCONTEXT *pDlgContext
)
{
    LVCOLUMN col;
    LPNMHDR  nhdr = (LPNMHDR)lParam;
    INT      item;

    EXTRASCALLBACK CallbackParam;

    if (nhdr == NULL)
        return;

    if (nhdr->idFrom != ID_IPCOBJECTSLIST)
        return;

    switch (nhdr->code) {

    case LVN_COLUMNCLICK:
        pDlgContext->bInverseSort = !pDlgContext->bInverseSort;

        CallbackParam.lParam = 0;
        CallbackParam.Value = pDlgContext->DialogMode;
        ListView_SortItemsEx(pDlgContext->ListView, &IpcDlgCompareFunc, (LPARAM)&CallbackParam);

        RtlSecureZeroMemory(&col, sizeof(col));
        col.mask = LVCF_IMAGE;

        if (pDlgContext->bInverseSort)
            col.iImage = 1;
        else
            col.iImage = 2;

        ListView_SetColumn(pDlgContext->ListView, 0, &col);
        break;

    case NM_DBLCLK:
        item = ((LPNMITEMACTIVATE)lParam)->iItem;
        if (item >= 0) {
            IpcDlgShowProperties(item, pDlgContext);
        }
        break;

    default:
        break;
    }
}

/*
* IpcDlgProc
*
* Purpose:
*
* Ipc objects window procedure.
*
*/
INT_PTR CALLBACK IpcDlgProc(
    _In_  HWND hwndDlg,
    _In_  UINT uMsg,
    _In_  WPARAM wParam,
    _In_  LPARAM lParam
)
{
    INT dlgIndex;
    EXTRASCONTEXT *pDlgContext;

    switch (uMsg) {
    case WM_NOTIFY:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_IPCDLGCONTEXT);
        if (pDlgContext) {
            IpcDlgHandleNotify(lParam, pDlgContext);
        }
        break;

    case WM_INITDIALOG:
        SetProp(hwndDlg, T_IPCDLGCONTEXT, (HANDLE)lParam);
        supCenterWindow(hwndDlg);
        break;

    case WM_DESTROY:
        RemoveProp(hwndDlg, T_IPCDLGCONTEXT);
        break;

    case WM_CLOSE:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_IPCDLGCONTEXT);
        if (pDlgContext) {

            ImageList_Destroy(pDlgContext->ImageList);

            dlgIndex = 0;
            if (pDlgContext->DialogMode == IpcModeMailSlots)
                dlgIndex = wobjIpcMailSlotsDlgId;
            else if (pDlgContext->DialogMode == IpcModeNamedPipes)
                dlgIndex = wobjIpcPipesDlgId;

            if ((dlgIndex == wobjIpcMailSlotsDlgId) ||
                (dlgIndex == wobjIpcPipesDlgId))
            {
                g_WinObj.AuxDialogs[dlgIndex] = NULL;
            }

            RtlSecureZeroMemory(pDlgContext, sizeof(EXTRASCONTEXT));
        }
        return DestroyWindow(hwndDlg);

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
* extrasCreateIpcDialog
*
* Purpose:
*
* Create and initialize IPC objects dialog.
*
*/
VOID extrasCreateIpcDialog(
    _In_ HWND hwndParent,
    _In_ IPC_DIALOG_MODE Mode
)
{
    INT      ResourceId = 0, dlgIndex;
    HWND     hwndDlg;
    HICON    hIcon;
    SIZE_T   sz = 0;
    LPWSTR   lpObjectsRoot = NULL, lpObjectRelativePath = NULL;
    LVCOLUMN col;

    EXTRASCONTEXT *pDlgContext;

    EXTRASCALLBACK CallbackParam;

    switch (Mode) {
    case IpcModeMailSlots:
        dlgIndex = wobjIpcMailSlotsDlgId;
        break;
    case IpcModeNamedPipes:
        dlgIndex = wobjIpcPipesDlgId;
        break;
    default:
        return;
    }

    //
    // Allow only one dialog.
    //
    if (g_WinObj.AuxDialogs[dlgIndex]) {
        SendMessage(g_WinObj.AuxDialogs[dlgIndex], WM_CLOSE, 0, 0);
    }

    RtlSecureZeroMemory(&IpcDlgContext[Mode], sizeof(EXTRASCONTEXT));
    pDlgContext = &IpcDlgContext[Mode];
    pDlgContext->DialogMode = Mode;

    hwndDlg = CreateDialogParam(g_WinObj.hInstance, MAKEINTRESOURCE(IDD_DIALOG_IPCOBJECTS),
        hwndParent, &IpcDlgProc, (LPARAM)pDlgContext);

    if (hwndDlg == NULL)
        return;

    pDlgContext->hwndDlg = hwndDlg;
    g_WinObj.AuxDialogs[dlgIndex] = hwndDlg;

    switch (Mode) {
    case IpcModeMailSlots:
        ResourceId = IDI_ICON_MAILSLOT;
        sz = DEVICE_MAILSLOT_LENGTH;
        lpObjectsRoot = DEVICE_MAILSLOT;
        SetWindowText(hwndDlg, TEXT("Mailslots"));
        break;
    case IpcModeNamedPipes:
        ResourceId = IDI_ICON_PIPE;
        sz = DEVICE_NAMED_PIPE_LENGTH;
        lpObjectsRoot = DEVICE_NAMED_PIPE;
        SetWindowText(hwndDlg, TEXT("Pipes"));
        break;
    default:
        lpObjectsRoot = NULL;
        break;
    }

    if (lpObjectsRoot == NULL)
        return;

    lpObjectRelativePath = (LPWSTR)supHeapAlloc(sz + 100);
    if (lpObjectRelativePath) {
        _strcpy(lpObjectRelativePath, TEXT("Relative Path ( "));
        _strcat(lpObjectRelativePath, lpObjectsRoot);
        _strcat(lpObjectRelativePath, TEXT(" )"));
        SetWindowText(GetDlgItem(hwndDlg, ID_IPCROOT), lpObjectRelativePath);
        supHeapFree(lpObjectRelativePath);
    }
    else
        return;

    //setup dlg listview
    pDlgContext->ListView = GetDlgItem(hwndDlg, ID_IPCOBJECTSLIST);
    if (pDlgContext->ListView) {
        pDlgContext->ImageList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 42, 8);
        if (pDlgContext->ImageList) {

            //set object icon
            hIcon = (HICON)LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(ResourceId), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
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
            ListView_SetImageList(pDlgContext->ListView, pDlgContext->ImageList, LVSIL_SMALL);
        }

        ListView_SetExtendedListViewStyle(pDlgContext->ListView,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

        SetWindowTheme(pDlgContext->ListView, TEXT("Explorer"), NULL);

        RtlSecureZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER | LVCF_IMAGE;
        col.iSubItem = 1;
        col.pszText = TEXT("Name");
        col.fmt = LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT;
        col.iOrder = 0;
        col.iImage = 2;
        col.cx = 500;
        ListView_InsertColumn(pDlgContext->ListView, 1, &col);

        IpcDlgQueryInfo(lpObjectsRoot, pDlgContext->ListView);

        CallbackParam.lParam = 0;
        CallbackParam.Value = Mode;
        ListView_SortItemsEx(pDlgContext->ListView, &IpcDlgCompareFunc, (LPARAM)&CallbackParam);
    }
}
