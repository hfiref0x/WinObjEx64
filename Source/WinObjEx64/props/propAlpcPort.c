/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2021
*
*  TITLE:       PROPALPCPORT.C
*
*  VERSION:     1.90
*
*  DATE:        31 May 2021
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

#define COLUMN_ALPCLIST_SERVER_PORT         0
#define COLUMN_ALPCLIST_CLIENT_PORT         1
#define COLUMN_ALPCLIST_CLIENT_EPROCESS     2
#define COLUMN_ALPCLIST_PROCESSNAME         3

/*
* AlpcPortListHandlePopupMenu
*
* Purpose:
*
* List popup construction.
*
*/
VOID AlpcPortListHandlePopupMenu(
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
* AlpcPortListCompareFunc
*
* Purpose:
*
* Listview comparer function.
*
*/
INT CALLBACK AlpcPortListCompareFunc(
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lpContextParam
)
{
    EXTRASCONTEXT* pDlgContext;

    pDlgContext = (EXTRASCONTEXT*)lpContextParam;
    if (pDlgContext == NULL)
        return 0;

    switch (pDlgContext->lvColumnToSort) {

    case COLUMN_ALPCLIST_SERVER_PORT:
    case COLUMN_ALPCLIST_CLIENT_PORT:
    case COLUMN_ALPCLIST_CLIENT_EPROCESS:
        return supGetMaxOfTwoU64FromHex(
            pDlgContext->ListView,
            lParam1,
            lParam2,
            pDlgContext->lvColumnToSort,
            pDlgContext->bInverseSort);

    case COLUMN_ALPCLIST_PROCESSNAME:
        return supGetMaxCompareTwoFixedStrings(
            pDlgContext->ListView,
            lParam1,
            lParam2,
            pDlgContext->lvColumnToSort,
            pDlgContext->bInverseSort);

    }

    return 0;
}

/*
* AlpcPortListHandleWMCommand
*
* Purpose:
*
* WM_COMMAND handler.
*
*/
VOID AlpcPortListHandleWMCommand(
    _In_ HWND hwndDlg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    EXTRASCONTEXT* pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);

    UNREFERENCED_PARAMETER(lParam);

    switch (GET_WM_COMMAND_ID(wParam, lParam)) {
    case ID_OBJECT_COPY:

        if (pDlgContext) {

            supListViewCopyItemValueToClipboard(pDlgContext->ListView,
                pDlgContext->lvItemHit,
                pDlgContext->lvColumnHit);

        }

        break;

    default:
        break;
    }
}

/*
* AlpcPortListHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for page listview.
*
*/
BOOL AlpcPortListHandleNotify(
    _In_ HWND hwndDlg,
    _In_ LPARAM lParam
)
{
    INT nImageIndex;
    LPNMLISTVIEW nhdr = (LPNMLISTVIEW)lParam;
    EXTRASCONTEXT* pDlgContext;

    if (nhdr == NULL) {
        return FALSE;
    }

    if (nhdr->hdr.idFrom != ID_ALPCLIST) {
        return FALSE;
    }

    switch (nhdr->hdr.code) {

    case LVN_COLUMNCLICK:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            pDlgContext->bInverseSort = !pDlgContext->bInverseSort;
            pDlgContext->lvColumnToSort = ((NMLISTVIEW*)nhdr)->iSubItem;

            ListView_SortItemsEx(
                pDlgContext->ListView,
                &AlpcPortListCompareFunc,
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

    default:
        break;
    }

    return FALSE;
}

typedef VOID(CALLBACK* POUTPUT_CLIENTS_CALLBACK)(
    _In_ HWND ListView,
    _In_ ULONG_PTR ServerPortAddress,
    _In_ ULONG_PTR ClientPortAddress,
    _In_ ULONG_PTR OwnerProcess
    );

typedef struct _ALPC_PORT_REF {
    union {
        union {
            ALPC_PORT_7600* Port7600;
            ALPC_PORT_9200* Port9200;
            ALPC_PORT_9600* Port9600;
            ALPC_PORT_10240* Port10240;
        } u1;
        PBYTE Ref;
    };
} ALPC_PORT_REF, * PALPC_PORT_REF;

/*
* AlpcPortEnumerateClients
*
* Purpose:
*
* Enumerate connected clients for given port.
*
*/
BOOL AlpcPortEnumerateClients(
    _In_ ULONG_PTR PortAddress,
    _In_ POUTPUT_CLIENTS_CALLBACK OutputCallback,
    _In_ HWND ListView,
    _Out_ PSIZE_T NumberOfClients
)
{
    BOOLEAN bSuccess = FALSE;
    ULONG objectSize = 0, objectVersion = 0;
    SIZE_T cEntries = 0;

    ULONG_PTR kernelAddress, comsListHead, serverPortAddress, clientPortAddress;

    LIST_ENTRY comsListEntry, comsNextEntry;
    ALPC_PORT_REF selfPort, clientPort;

    ALPC_COMMUNICATION_INFO_COMPAT comsInfo;

    ULONG offset = FIELD_OFFSET(ALPC_COMMUNICATION_INFO_COMPAT, CommunicationList);

   
    *NumberOfClients = 0;

    //
    // Dump ALPC_PORT.
    //
    selfPort.Ref = (PBYTE)ObDumpAlpcPortObjectVersionAware(PortAddress,
        &objectSize,
        &objectVersion);

    if (selfPort.Ref == NULL) {
        return FALSE;
    }

    do {

        kernelAddress = (ULONG_PTR)selfPort.u1.Port7600->CommunicationInfo;
        comsListHead = kernelAddress + offset;

        comsListEntry.Flink = comsListEntry.Blink = NULL;

        //
        // Read entry head.
        //
        if (!kdReadSystemMemory(comsListHead,
            &comsListEntry,
            sizeof(LIST_ENTRY)))
        {
            break;
        }

        //
        // Walk list entries.
        //
        while ((ULONG_PTR)comsListEntry.Flink != comsListHead) {

            kernelAddress = (ULONG_PTR)comsListEntry.Flink - offset;

            RtlSecureZeroMemory(&comsInfo, sizeof(comsInfo));

            if (!kdReadSystemMemory(kernelAddress,
                &comsInfo,
                sizeof(comsInfo)))
            {
                break;
            }
            

            serverPortAddress = (ULONG_PTR)comsInfo.ServerCommunicationPort;
            clientPortAddress = (ULONG_PTR)comsInfo.ClientCommunicationPort;
            clientPort.Ref = (PBYTE)ObDumpAlpcPortObjectVersionAware(clientPortAddress,
                &objectSize,
                &objectVersion);

            if (clientPort.Ref) {

                OutputCallback(
                    ListView,
                    serverPortAddress,
                    clientPortAddress,
                    (ULONG_PTR)clientPort.u1.Port7600->OwnerProcess);

                cEntries += 1;

                supVirtualFree(selfPort.Ref);
            }
            else {
                break;
            }

            //
            // Read next entry.
            //
            comsListEntry = comsInfo.CommunicationList;

            comsNextEntry.Flink = comsNextEntry.Blink = NULL;

            if (!kdReadSystemMemoryEx(
                (ULONG_PTR)comsListEntry.Flink,
                &comsNextEntry,
                sizeof(LIST_ENTRY),
                NULL))
            {
                break;
            }

            if (comsNextEntry.Flink == NULL)
                break;
        }

        bSuccess = TRUE;

    } while (FALSE);

    *NumberOfClients = cEntries;

    supVirtualFree(selfPort.Ref);

    return bSuccess;
}

/*
* AlpcPortEnumerateCallback
*
* Purpose:
*
* Connected clients enumeration output callback.
*
*/
VOID CALLBACK AlpcPortEnumerateCallback(
    _In_ HWND ListView,
    _In_ ULONG_PTR ServerPortAddress,
    _In_ ULONG_PTR ClientPortAddress,
    _In_ ULONG_PTR OwnerProcess
)
{
    BOOLEAN bExtQuery = FALSE;
    UNICODE_STRING usImageFileName;
    PUNICODE_STRING pusFileName = NULL;

    INT nIndex;
    LVITEM lvitem;

    HANDLE processId = NULL;

    WCHAR szBuffer[MAX_PATH * 2];

    //
    // ServerPortAddress
    //
    szBuffer[0] = L'0';
    szBuffer[1] = L'x';
    szBuffer[2] = 0;
    u64tohex(ServerPortAddress, &szBuffer[2]);

    RtlSecureZeroMemory(&lvitem, sizeof(lvitem));

    lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
    lvitem.pszText = szBuffer;
    lvitem.iItem = MAXINT;
    nIndex = ListView_InsertItem(ListView, &lvitem);

    //
    // ClientPortAddress
    //
    szBuffer[0] = L'0';
    szBuffer[1] = L'x';
    szBuffer[2] = 0;
    u64tohex(ClientPortAddress, &szBuffer[2]);

    lvitem.mask = LVIF_TEXT;
    lvitem.iSubItem++;
    lvitem.iItem = nIndex;
    ListView_SetItem(ListView, &lvitem);

    //
    // EPROCESS
    //
    szBuffer[0] = L'0';
    szBuffer[1] = L'x';
    szBuffer[2] = 0;
    u64tohex(OwnerProcess, &szBuffer[2]);

    lvitem.iSubItem++;
    ListView_SetItem(ListView, &lvitem);

    //
    // Process Name
    //
    RtlInitEmptyUnicodeString(&usImageFileName, NULL, 0);

    if (ObGetProcessId(OwnerProcess, &processId)) {

        bExtQuery = NT_SUCCESS(supQueryProcessImageFileNameWin32(processId, &pusFileName));

        if (bExtQuery) {

            if (pusFileName->Buffer && pusFileName->Length) {

                lvitem.pszText = supExtractFileName(pusFileName->Buffer);

            }
            else {
                bExtQuery = FALSE;
            }
            
        }

    }

    if (bExtQuery == FALSE) {

        if (ObGetProcessImageFileName(OwnerProcess, &usImageFileName)) {
            lvitem.pszText = usImageFileName.Buffer;
        }
        else {
            _strcpy(szBuffer, T_Unknown);
            lvitem.pszText = szBuffer;
        }
    
    }

    lvitem.iSubItem++;
    ListView_SetItem(ListView, &lvitem);

    if (pusFileName)
        supHeapFree(pusFileName);

    if (usImageFileName.Buffer)
        RtlFreeUnicodeString(&usImageFileName);
}

/*
* AlpcPortListSetInfo
*
* Purpose:
*
* Query information and fill listview.
* Called each time when page became visible.
*
*/
VOID AlpcPortListSetInfo(
    _In_ HWND hwndDlg,
    _In_ PROP_OBJECT_INFO* Context,
    _In_ EXTRASCONTEXT* pDlgContext
)
{
    SIZE_T cEntries = 0;
    WCHAR szBuffer[100];

    ListView_DeleteAllItems(pDlgContext->ListView);
    supListViewEnableRedraw(pDlgContext->ListView, FALSE);

    if (AlpcPortEnumerateClients(Context->ObjectInfo.ObjectAddress,
        (POUTPUT_CLIENTS_CALLBACK)AlpcPortEnumerateCallback,
        pDlgContext->ListView,
        &cEntries))
    {

        RtlStringCchPrintfSecure(szBuffer, 100, TEXT("%llu connections"), cEntries);
        SetDlgItemText(hwndDlg, ID_ALPCLISTMSG, szBuffer);

    }
    else {

        SetDlgItemText(hwndDlg, ID_ALPCLISTMSG, TEXT("Error, not all connections listed"));

    }
    supListViewEnableRedraw(pDlgContext->ListView, TRUE);
}

/*
* AlpcPortListCreate
*
* Purpose:
*
* Initialize listview.
* Called once.
*
*/
VOID AlpcPortListCreate(
    _In_ HWND hwndDlg,
    _In_ EXTRASCONTEXT* pDlgContext
)
{
    HICON hImage;
    LVCOLUMNS_DATA columnData[] =
    {
        { L"Server Port", 140, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT, 2 },
        { L"Client Port", 130, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT, I_IMAGENONE },
        { L"Client EPROCESS", 130, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT, I_IMAGENONE },
        { L"Client Name", 130, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT, I_IMAGENONE }
    };

    pDlgContext->ListView = GetDlgItem(hwndDlg, ID_ALPCLIST);
    if (pDlgContext->ListView == NULL)
        return;

    pDlgContext->ImageList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 8, 8);
    if (pDlgContext->ImageList) {

        //port image
        hImage = (HICON)LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(IDI_ICON_PORT),
            IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);

        if (hImage) {
            ImageList_ReplaceIcon(pDlgContext->ImageList, -1, hImage);
            DestroyIcon(hImage);
        }

        //sort images
        hImage = (HICON)LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(IDI_ICON_SORTUP),
            IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);

        if (hImage) {
            ImageList_ReplaceIcon(pDlgContext->ImageList, -1, hImage);
            DestroyIcon(hImage);
        }
        hImage = (HICON)LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(IDI_ICON_SORTDOWN),
            IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);

        if (hImage) {
            ImageList_ReplaceIcon(pDlgContext->ImageList, -1, hImage);
            DestroyIcon(hImage);
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

    //
    // And columns and remember their count.
    //
    pDlgContext->lvColumnCount = supAddLVColumnsFromArray(
        pDlgContext->ListView,
        columnData,
        RTL_NUMBER_OF(columnData));

}

/*
* AlpcPortListDialogProc
*
* Purpose:
*
* ALPC Port connections list page.
*
* WM_INITDIALOG - Initialize listview.
* WM_NOTIFY - Handle list view notifications.
* WM_SHOWWINDOW - Collect info and fill list.
* WM_DESTROY - Free image list.
*
*/
INT_PTR CALLBACK AlpcPortListDialogProc(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    PROPSHEETPAGE* pSheet;
    PROP_OBJECT_INFO* Context = NULL;
    EXTRASCONTEXT* pDlgContext = NULL;

    switch (uMsg) {

    case WM_SHOWWINDOW:
        if (wParam) {
            Context = (PROP_OBJECT_INFO*)GetProp(hwndDlg, T_PROPCONTEXT);
            pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
            if (Context && pDlgContext) {

                AlpcPortListSetInfo(hwndDlg, Context, pDlgContext);
                if (pDlgContext->ListView) {

                    ListView_SortItemsEx(
                        pDlgContext->ListView,
                        &AlpcPortListCompareFunc,
                        pDlgContext);
                }

            }
        }
        break;

    case WM_NOTIFY:
        return AlpcPortListHandleNotify(hwndDlg, lParam);

    case WM_COMMAND:      
        AlpcPortListHandleWMCommand(hwndDlg, wParam, lParam);
        break;

    case WM_DESTROY:
        pDlgContext = (EXTRASCONTEXT*)RemoveProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            if (pDlgContext->ImageList) {
                ImageList_Destroy(pDlgContext->ImageList);
            }
            supHeapFree(pDlgContext);
        }
        RemoveProp(hwndDlg, T_PROPCONTEXT);
        break;

    case WM_INITDIALOG:
        pSheet = (PROPSHEETPAGE*)lParam;
        if (pSheet) {
            SetProp(hwndDlg, T_PROPCONTEXT, (HANDLE)pSheet->lParam);
            pDlgContext = (EXTRASCONTEXT*)supHeapAlloc(sizeof(EXTRASCONTEXT));
            if (pDlgContext) {
                pDlgContext->lvColumnHit = -1;
                pDlgContext->lvItemHit = -1;
                SetProp(hwndDlg, T_DLGCONTEXT, (HANDLE)pDlgContext);
                AlpcPortListCreate(hwndDlg, pDlgContext);
            }
        }
        break;

    case WM_CONTEXTMENU:

        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            supHandleContextMenuMsgForListView(hwndDlg,
                wParam,
                lParam,
                pDlgContext->ListView,
                (pfnPopupMenuHandler)AlpcPortListHandlePopupMenu,
                pDlgContext);
        }
        break;

    default:
        return FALSE;

    }
    return TRUE;
}
