/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2022
*
*  TITLE:       EXTRASIPC.C
*
*  VERSION:     2.00
*
*  DATE:        19 Jun 2022
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
#include "propDlg.h"
#include "props.h"

//mailslot root
#define DEVICE_MAILSLOT          L"\\Device\\Mailslot\\"
#define DEVICE_MAILSLOT_LENGTH   sizeof(DEVICE_MAILSLOT) - sizeof(WCHAR)

//named pipes root
#define DEVICE_NAMED_PIPE        L"\\Device\\NamedPipe\\"
#define DEVICE_NAMED_PIPE_LENGTH sizeof(DEVICE_NAMED_PIPE) - sizeof(WCHAR)

#define ID_IPCLIST_REFRESH  ID_VIEW_REFRESH

//maximum number of possible pages
#define EXTRAS_IPC_MAX_PAGE 2

static HPROPSHEETPAGE IpcPages[EXTRAS_IPC_MAX_PAGE];//object, security
static EXTRASCONTEXT IpcDlgContext[EXTRAS_IPC_MAX_PAGE];

static HANDLE IpcDlgThreadHandles[EXTRAS_IPC_MAX_PAGE] = { NULL, NULL };
static FAST_EVENT IpcDlgInitializedEvents[EXTRAS_IPC_MAX_PAGE] = { FAST_EVENT_INIT, FAST_EVENT_INIT };

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
    _In_ IPC_DLG_MODE DialogMode
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
    _In_ IPC_DLG_MODE Mode
)
{
    LPWSTR lpFullName = NULL, lpRootDirectory = NULL;
    SIZE_T sz;

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
    _In_ PROP_OBJECT_INFO* Context,
    _Inout_ PHANDLE phObject,
    _In_ ACCESS_MASK DesiredAccess
)
{
    BOOL                bResult = FALSE;
    HANDLE              hObject;
    NTSTATUS            status;
    OBJECT_ATTRIBUTES   obja;
    IO_STATUS_BLOCK     iost;

    *phObject = NULL;

    hObject = NULL;
    InitializeObjectAttributes(&obja, &Context->NtObjectPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenFile(&hObject, DesiredAccess, &obja, &iost,
        FILE_SHARE_VALID_FLAGS, FILE_NON_DIRECTORY_FILE);

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
    _In_ PROP_OBJECT_INFO* Context,
    _In_ HWND hwndDlg
)
{
    HANDLE          hMailslot;
    NTSTATUS        status;
    WCHAR           szBuffer[MAX_PATH];
    IO_STATUS_BLOCK iost;

    FILE_MAILSLOT_QUERY_INFORMATION fmqi;

    hMailslot = NULL;
    if (!IpcOpenObjectMethod(Context, &hMailslot, GENERIC_READ)) {
        //on error display last win32 error
        IpcDisplayError(hwndDlg, IpcModeMailSlots);
        return;
    }

    supDisplayCurrentObjectPath(
        GetDlgItem(hwndDlg, ID_MAILSLOT_FULLPATH), 
        &Context->NtObjectPath, 
        FALSE);

    RtlSecureZeroMemory(&fmqi, sizeof(fmqi));
    status = NtQueryInformationFile(hMailslot, &iost, &fmqi, sizeof(fmqi), FileMailslotQueryInformation);
    if (NT_SUCCESS(status)) {
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

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
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
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
    _In_ PROP_OBJECT_INFO* Context,
    _In_ HWND hwndDlg
)
{
    LPWSTR                      lpType;
    HANDLE                      hPipe;
    NTSTATUS                    status;
    WCHAR                       szBuffer[64];
    IO_STATUS_BLOCK             iost;
    FILE_PIPE_LOCAL_INFORMATION fpli;

    supDisplayCurrentObjectPath(GetDlgItem(hwndDlg, ID_PIPE_FULLPATH), 
        &Context->NtObjectPath, 
        FALSE);

    //open pipe
    hPipe = NULL;
    if (!IpcOpenObjectMethod(Context, &hPipe, GENERIC_READ)) {

        // for pipes created with PIPE_ACCESS_INBOUND open mode 
        // https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea

        if (!IpcOpenObjectMethod(Context, &hPipe, GENERIC_WRITE | FILE_READ_ATTRIBUTES)) {
            IpcDisplayError(hwndDlg, IpcModeNamedPipes);
            return;
        }
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

        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

        //CurrentInstances
        ultostr(fpli.CurrentInstances, szBuffer);
        SetDlgItemText(hwndDlg, ID_PIPE_CURINSTANCES, szBuffer);

        //MaximumInstances
        if (fpli.MaximumInstances == MAXDWORD) {
            _strcpy(szBuffer, TEXT("Unlimited"));
        }
        else {
            ultostr(fpli.MaximumInstances, szBuffer);
        }
        SetDlgItemText(hwndDlg, ID_PIPE_MAXINSTANCES, szBuffer);

        //InboundQuota
        ultostr(fpli.InboundQuota, szBuffer);
        SetDlgItemText(hwndDlg, ID_PIPE_INBUFFER, szBuffer);

        //OutboundQuota
        ultostr(fpli.OutboundQuota, szBuffer);
        SetDlgItemText(hwndDlg, ID_PIPE_OUTBUFFER, szBuffer);

        //WriteQuotaAvailable
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
    PROPSHEETPAGE* pSheet = NULL;
    PROP_OBJECT_INFO* Context = NULL;
    HICON             hIcon;

    EXTRASCONTEXT* pDlgContext;

    switch (uMsg) {

    case WM_INITDIALOG:
        pSheet = (PROPSHEETPAGE*)lParam;
        if (pSheet) {
            SetProp(hwndDlg, T_PROPCONTEXT, (HANDLE)pSheet->lParam);
            Context = (PROP_OBJECT_INFO*)pSheet->lParam;
            if (Context) {
                pDlgContext = (EXTRASCONTEXT*)Context->ExtrasContext;
                if (pDlgContext) {

                    hIcon = ImageList_GetIcon(pDlgContext->ImageList,
                        0,
                        ILD_NORMAL | ILD_TRANSPARENT);
                    if (hIcon) {

                        SendDlgItemMessage(hwndDlg, ID_OBJECT_ICON,
                            STM_SETIMAGE, IMAGE_ICON, (LPARAM)hIcon);

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
                pDlgContext = (EXTRASCONTEXT*)Context->ExtrasContext;
                if (pDlgContext) {
                    switch (pDlgContext->DialogMode) {
                    case IpcModeMailSlots:
                        IpcMailslotQueryInfo(Context, hwndDlg);
                        break;
                    case IpcModeNamedPipes:
                        IpcPipeQueryInfo(Context, hwndDlg);
                        break;
                    }
                }
            }
        }
        return 1;
        break;

    case WM_DESTROY:
        Context = (PROP_OBJECT_INFO*)RemoveProp(hwndDlg, T_PROPCONTEXT);
        if (Context) {
            pDlgContext = (EXTRASCONTEXT*)Context->ExtrasContext;
            if (pDlgContext) {
                DestroyIcon(pDlgContext->ObjectIcon);
                pDlgContext->ObjectIcon = NULL;
            }
        }
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
    _In_ EXTRASCONTEXT* pDlgContext
)
{
    INT nPages = 0;
    PROP_OBJECT_INFO* Context;
    HPROPSHEETPAGE SecurityPage = NULL;
    PROPSHEETPAGE Page;
    PROPSHEETHEADER PropHeader;
    WCHAR szCaption[MAX_PATH];
    PROP_CONFIG propConfig;

    LPWSTR objectName, objectPathCombined;
    UNICODE_STRING objectPathNt;

    RtlSecureZeroMemory(&propConfig, sizeof(propConfig));
    propConfig.ContextType = propNormal;
    propConfig.ObjectTypeIndex = ObjectTypeFile;

    objectName = supGetItemText(pDlgContext->ListView, iItem, 0, NULL);
    objectPathCombined = IpcCreateObjectPathWithName(objectName,
        (IPC_DLG_MODE)pDlgContext->DialogMode);

    RtlInitUnicodeString(&objectPathNt, objectPathCombined);
    propConfig.NtObjectPath = &objectPathNt;

    Context = propContextCreate(&propConfig);
    if (Context == NULL)
        return;

    Context->ExtrasContext = (PVOID)pDlgContext;

    supHeapFree(objectName);

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
            SI_EDIT_AUDITS | SI_EDIT_OWNER | SI_EDIT_PERMS | //psiFlags
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
    EXTRASCONTEXT* pDlgContext;
    EXTRASCALLBACK* CallbackParam = (EXTRASCALLBACK*)lParamSort;

    if (CallbackParam == NULL)
        return 0;

    pDlgContext = &IpcDlgContext[CallbackParam->Value];

    return supListViewBaseComparer(pDlgContext->ListView,
        pDlgContext->bInverseSort,
        lParam1,
        lParam2,
        (LPARAM)CallbackParam->lParam);
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
    _In_ IPC_DLG_MODE Mode,
    _In_ BOOL bRefresh,
    _In_ HWND ListView
)
{
    BOOLEAN                     bRestartScan;
    ULONG                       QuerySize;
    HANDLE                      hObject = NULL;
    LPWSTR                      lpObjectRoot;
    FILE_DIRECTORY_INFORMATION* DirectoryInfo = NULL;
    NTSTATUS                    status;
    OBJECT_ATTRIBUTES           obja;
    UNICODE_STRING              uStr;
    IO_STATUS_BLOCK             iost;
    LVITEM                      lvitem;
    INT                         c;

    EXTRASCALLBACK callbackParam;

    if (Mode == IpcModeMailSlots)
        lpObjectRoot = DEVICE_MAILSLOT;
    else
        lpObjectRoot = DEVICE_NAMED_PIPE;

    if (bRefresh)
        ListView_DeleteAllItems(ListView);

    __try {

        RtlInitUnicodeString(&uStr, lpObjectRoot);
        InitializeObjectAttributes(&obja, &uStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = NtOpenFile(
            &hObject,
            FILE_LIST_DIRECTORY,
            &obja,
            &iost,
            FILE_SHARE_VALID_FLAGS,
            0);

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

            if ((!NT_SUCCESS(status)) ||
                (!NT_SUCCESS(iost.Status)) ||
                (iost.Information == 0))
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

        if (AbnormalTermination())
            supReportAbnormalTermination(__FUNCTIONW__);

        if (DirectoryInfo != NULL) {
            supHeapFree(DirectoryInfo);
        }

        if (hObject) {
            NtClose(hObject);
        }

        callbackParam.lParam = 0;
        callbackParam.Value = Mode;
        ListView_SortItemsEx(ListView, &IpcDlgCompareFunc, (LPARAM)&callbackParam);

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
BOOL IpcDlgHandleNotify(
    _In_ HWND hwndDlg,
    _In_ LPARAM lParam
)
{
    LVCOLUMN col;
    LPNMHDR  nhdr = (LPNMHDR)lParam;
    INT      item;

    EXTRASCONTEXT* pDlgContext;
    EXTRASCALLBACK CallbackParam;

    if (nhdr == NULL)
        return FALSE;

    if (nhdr->idFrom != ID_IPCOBJECTSLIST)
        return FALSE;

    pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_IPCDLGCONTEXT);
    if (pDlgContext == NULL)
        return FALSE;

    switch (nhdr->code) {

    case LVN_COLUMNCLICK:
        pDlgContext->bInverseSort = (~pDlgContext->bInverseSort) & 1;

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
        item = ((LPNMLISTVIEW)lParam)->iItem;
        if (item >= 0) {
            IpcDlgShowProperties(item, pDlgContext);
        }
        break;

    default:
        return FALSE;
    }

    return TRUE;
}

/*
* IpcDlgHandlePopupMenu
*
* Purpose:
*
* Popup menu construction.
*
*/
VOID IpcDlgHandlePopupMenu(
    _In_ HWND hwndDlg,
    _In_ LPPOINT lpPoint,
    _In_ PVOID lpUserParam
)
{
    HMENU hMenu;
    UINT uPos = 0;
    EXTRASCONTEXT* Context = (EXTRASCONTEXT*)lpUserParam;

    hMenu = CreatePopupMenu();
    if (hMenu) {

        InsertMenu(hMenu, uPos++, MF_BYCOMMAND, ID_OBJECT_PROPERTIES, T_PROPERTIES);

        if (supListViewAddCopyValueItem(hMenu,
            Context->ListView,
            ID_OBJECT_COPY,
            uPos++,
            lpPoint,
            &Context->lvItemHit,
            &Context->lvColumnHit))
        {
            InsertMenu(hMenu, uPos++, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
        }

        InsertMenu(hMenu, uPos++, MF_BYCOMMAND, ID_IPCLIST_REFRESH, T_VIEW_REFRESH);

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
* IpcDlgOnInit
*
* Purpose:
*
* Ipc dialog WM_INITDIALOG handler.
*
*/
VOID IpcDlgOnInit(
    _In_  HWND hwndDlg,
    _In_  LPARAM lParam
)
{
    INT iResId = 0;
    HICON hIcon;
    SIZE_T sz = 0;
    LPWSTR lpObjectsRoot = NULL, lpObjectRelativePath = NULL;
    EXTRASCONTEXT* pDlgContext = (EXTRASCONTEXT*)lParam;

    SetProp(hwndDlg, T_IPCDLGCONTEXT, (HANDLE)lParam);
    supCenterWindowSpecifyParent(hwndDlg, g_hwndMain);

    pDlgContext->lvColumnHit = -1;
    pDlgContext->lvItemHit = -1;
    pDlgContext->hwndDlg = hwndDlg;

    switch (pDlgContext->DialogMode) {
    case IpcModeMailSlots:
        iResId = IDI_ICON_MAILSLOT;
        sz = DEVICE_MAILSLOT_LENGTH;
        lpObjectsRoot = DEVICE_MAILSLOT;
        SetWindowText(hwndDlg, TEXT("Mailslots"));
        break;
    default:
        iResId = IDI_ICON_PIPE;
        sz = DEVICE_NAMED_PIPE_LENGTH;
        lpObjectsRoot = DEVICE_NAMED_PIPE;
        SetWindowText(hwndDlg, TEXT("Pipes"));
        break;
    }

    lpObjectRelativePath = (LPWSTR)supHeapAlloc(sz + 100);
    if (lpObjectRelativePath) {
        _strcpy(lpObjectRelativePath, TEXT("Relative Path ( "));
        _strcat(lpObjectRelativePath, lpObjectsRoot);
        _strcat(lpObjectRelativePath, TEXT(" )"));
        SetDlgItemText(hwndDlg, ID_IPCROOT, lpObjectRelativePath);
        supHeapFree(lpObjectRelativePath);
    }

    //setup dlg listview
    pDlgContext->ListView = GetDlgItem(hwndDlg, ID_IPCOBJECTSLIST);
    if (pDlgContext->ListView) {
        pDlgContext->ImageList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 42, 8);
        if (pDlgContext->ImageList) {

            //set object icon
            hIcon = (HICON)LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(iResId), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
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
        }

        //
        // Set listview imagelist, style flags and theme.
        //
        supSetListViewSettings(pDlgContext->ListView,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP,
            FALSE,
            TRUE,
            pDlgContext->ImageList,
            LVSIL_SMALL);

        supAddListViewColumn(pDlgContext->ListView, 0, 0, 0,
            2,
            LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,
            TEXT("Name"), 500);

        supListViewEnableRedraw(pDlgContext->ListView, FALSE);

        IpcDlgQueryInfo((IPC_DLG_MODE)pDlgContext->DialogMode, FALSE, pDlgContext->ListView);

        supListViewEnableRedraw(pDlgContext->ListView, TRUE);
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
    INT nSelected;
    EXTRASCONTEXT* pDlgContext;

    if (uMsg == g_WinObj.SettingsChangeMessage) {
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_IPCDLGCONTEXT);
        if (pDlgContext) {
            extrasHandleSettingsChange(pDlgContext);
        }
        return TRUE;
    }

    switch (uMsg) {
    case WM_NOTIFY:
        return IpcDlgHandleNotify(hwndDlg, lParam);

    case WM_INITDIALOG:
        IpcDlgOnInit(hwndDlg, lParam);
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    case WM_CLOSE:
        pDlgContext = (EXTRASCONTEXT*)RemoveProp(hwndDlg, T_IPCDLGCONTEXT);
        if (pDlgContext) {
            ImageList_Destroy(pDlgContext->ImageList);
        }
        DestroyWindow(hwndDlg);
        break;

    case WM_COMMAND:

        switch (GET_WM_COMMAND_ID(wParam, lParam)) {

        case IDCANCEL:
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            break;

        case ID_IPCLIST_REFRESH:
            pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_IPCDLGCONTEXT);
            if (pDlgContext) {

                supListViewEnableRedraw(pDlgContext->ListView, FALSE);

                IpcDlgQueryInfo((IPC_DLG_MODE)pDlgContext->DialogMode, TRUE, pDlgContext->ListView);

                supListViewEnableRedraw(pDlgContext->ListView, TRUE);

            }
            break;

        case ID_OBJECT_COPY:
            pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_IPCDLGCONTEXT);
            if (pDlgContext) {
                supListViewCopyItemValueToClipboard(pDlgContext->ListView,
                    pDlgContext->lvItemHit,
                    pDlgContext->lvColumnHit);
            }
            break;

        case ID_OBJECT_PROPERTIES:

            pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_IPCDLGCONTEXT);
            if (pDlgContext) {
                if (ListView_GetSelectedCount(pDlgContext->ListView)) {
                    nSelected = ListView_GetSelectionMark(pDlgContext->ListView);
                    if (nSelected >= 0) {
                        IpcDlgShowProperties(nSelected, pDlgContext);
                    }
                }
            }

            break;
        }

        break;

    case WM_CONTEXTMENU:

        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_IPCDLGCONTEXT);
        if (pDlgContext) {
            supHandleContextMenuMsgForListView(hwndDlg,
                wParam,
                lParam,
                pDlgContext->ListView,
                (pfnPopupMenuHandler)IpcDlgHandlePopupMenu,
                pDlgContext);
        }
        break;

    }

    return FALSE;
}

/*
* extrasIpcDialogWorkerThread
*
* Purpose:
*
* IPC objects dialog worker thread.
*
*/
DWORD extrasIpcDialogWorkerThread(
    _In_ PVOID Parameter
)
{
    HWND hwndDlg;
    BOOL bResult;
    MSG message;
    HACCEL acceleratorTable;
    HANDLE workerThread;
    FAST_EVENT fastEvent;
    EXTRASCONTEXT* pDlgContext = (EXTRASCONTEXT*)Parameter;

    hwndDlg = CreateDialogParam(g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_IPCOBJECTS),
        0,
        &IpcDlgProc,
        (LPARAM)pDlgContext);

    acceleratorTable = LoadAccelerators(g_WinObj.hInstance, MAKEINTRESOURCE(IDR_ACCELERATOR1));

    fastEvent = IpcDlgInitializedEvents[pDlgContext->DialogMode];

    supSetFastEvent(&fastEvent);

    do {

        bResult = GetMessage(&message, NULL, 0, 0);
        if (bResult == -1)
            break;

        if (IsDialogMessage(hwndDlg, &message)) {
            TranslateAccelerator(hwndDlg, acceleratorTable, &message);
        }
        else {
            TranslateMessage(&message);
            DispatchMessage(&message);
        }

    } while (bResult != 0);

    supResetFastEvent(&fastEvent);

    if (acceleratorTable)
        DestroyAcceleratorTable(acceleratorTable);

    workerThread = IpcDlgThreadHandles[pDlgContext->DialogMode];
    if (workerThread) {
        NtClose(workerThread);
        IpcDlgThreadHandles[pDlgContext->DialogMode] = NULL;
    }

    return 0;
}

/*
* extrasCreateIpcDialog
*
* Purpose:
*
* Run IPC objects dialog worker thread.
*
*/
VOID extrasCreateIpcDialog(
    _In_ IPC_DLG_MODE Mode
)
{
    if (Mode < 0 || Mode >= IpcMaxMode)
        return;

    if (!IpcDlgThreadHandles[Mode]) {

        RtlSecureZeroMemory(&IpcDlgContext[Mode], sizeof(EXTRASCONTEXT));
        IpcDlgContext[Mode].DialogMode = Mode;
        IpcDlgThreadHandles[Mode] = supCreateDialogWorkerThread(extrasIpcDialogWorkerThread, (PVOID)&IpcDlgContext[Mode], 0);
        supWaitForFastEvent(&IpcDlgInitializedEvents[Mode], NULL);

    }

}
