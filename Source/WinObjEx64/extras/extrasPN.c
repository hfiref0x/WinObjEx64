/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019
*
*  TITLE:       EXTRASPN.C
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
#include "extras.h"
#include "extrasPN.h"
#include "propDlg.h"

EXTRASCONTEXT PnDlgContext;
OBJECT_COLLECTION PNSCollection;
ULONG PNSNumberOfObjects = 0;

#ifdef _USE_OWN_DRIVER
#define T_NAMESPACEQUERYFAILED TEXT("Unable to list namespaces! Make sure you run this program as Admin.")
#else
#define T_NAMESPACEQUERYFAILED TEXT("Unable to list namespaces! Make sure you run this program as Admin and Windows is in a DEBUG mode.")
#endif

#define T_NAMESPACENOTHING TEXT("No private namespaces found.")



/*
* PNDlgShowObjectProperties
*
* Purpose:
*
* Show selected object properties.
*
*/
VOID PNDlgShowObjectProperties(
    VOID
)
{
    INT                 nSelected;
    LPWSTR              lpType, lpName;
    POBJREF             objRef = NULL;

    OBJREFPNS           pnsInfo;
    PROP_NAMESPACE_INFO propNamespace;
    PROP_DIALOG_CREATE_SETTINGS propSettings;

    //
    // Only one namespace object properties dialog at the same time allowed.
    //
    if (g_NamespacePropWindow != NULL) {
        SetActiveWindow(g_NamespacePropWindow);
        return;
    }

    if (ListView_GetSelectedCount(PnDlgContext.ListView) == 0) {
        return;
    }

    nSelected = ListView_GetSelectionMark(PnDlgContext.ListView);
    if (nSelected == -1) {
        return;
    }

    //
    //  Get ref to object, failure here is critical.
    //
    if (!supGetListViewItemParam(PnDlgContext.ListView, nSelected, (PVOID*)&objRef))
        return;

    if (objRef == NULL)
        return;

    RtlCopyMemory(&pnsInfo, &objRef->PrivateNamespace, sizeof(OBJREFPNS));
    RtlSecureZeroMemory(&propNamespace, sizeof(propNamespace));

    propNamespace.ObjectAddress = objRef->ObjectAddress;

    //
    // Dump boundary descriptor, failure here is critical.
    //
    if (!NT_SUCCESS(ObCopyBoundaryDescriptor(
        (OBJECT_NAMESPACE_ENTRY*)pnsInfo.NamespaceLookupEntry,
        &propNamespace.BoundaryDescriptor,
        &propNamespace.SizeOfBoundaryDescriptor)))
    {
        return;
    }

    lpName = supGetItemText(PnDlgContext.ListView, nSelected, 0, NULL);
    if (lpName) {
        lpType = supGetItemText(PnDlgContext.ListView, nSelected, 1, NULL);
        if (lpType) {

            RtlSecureZeroMemory(&propSettings, sizeof(propSettings));

            propSettings.lpObjectName = lpName;
            propSettings.lpObjectType = lpType;
            propSettings.NamespaceObject = &propNamespace;

            propCreateDialog(&propSettings);

            supHeapFree(lpType);
        }
        supHeapFree(lpName);
    }
    //
    // propNamespace.BoundaryDescriptor will be freed by propDestroyContext.
    // 
}

/*
* PNListCompareFunc
*
* Purpose:
*
* Main window listview comparer function.
*
*/
INT CALLBACK PNListCompareFunc(
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort
)
{
    LPWSTR lpItem1 = NULL, lpItem2 = NULL;
    INT    nResult = 0;

    //
    // Sort addresses.
    //
    if (lParamSort == 2) {
        return supGetMaxOfTwoU64FromHex(
            PnDlgContext.ListView,
            lParam1,
            lParam2,
            lParamSort,
            PnDlgContext.bInverseSort);
    }

    lpItem1 = supGetItemText(PnDlgContext.ListView, (INT)lParam1, (INT)lParamSort, NULL);
    lpItem2 = supGetItemText(PnDlgContext.ListView, (INT)lParam2, (INT)lParamSort, NULL);

    if ((lpItem1 == NULL) && (lpItem2 == NULL)) {
        nResult = 0;
        goto Done;
    }
    if ((lpItem1 == NULL) && (lpItem2 != NULL)) {
        nResult = (PnDlgContext.bInverseSort) ? 1 : -1;
        goto Done;
    }
    if ((lpItem2 == NULL) && (lpItem1 != NULL)) {
        nResult = (PnDlgContext.bInverseSort) ? -1 : 1;
        goto Done;
    }

    if (PnDlgContext.bInverseSort)
        nResult = _strcmpi(lpItem2, lpItem1);
    else
        nResult = _strcmpi(lpItem1, lpItem2);

Done:
    if (lpItem1) supHeapFree(lpItem1);
    if (lpItem2) supHeapFree(lpItem2);

    return nResult;
}

/*
* PNDlgEnumerateCallback
*
* Purpose:
*
* Callback for private namespaces output.
*
*/
BOOL CALLBACK PNDlgEnumerateCallback(
    _In_ POBJREF Entry,
    _In_opt_ PVOID Context
)
{
    INT     index;
    UINT    ConvertedTypeIndex;
    LPCWSTR TypeName;

    LVITEM  lvitem;
    WCHAR   szBuffer[MAX_PATH + 1];

    UNREFERENCED_PARAMETER(Context);

    ConvertedTypeIndex = supGetObjectNameIndexByTypeIndex(
        (PVOID)Entry->ObjectAddress,
        Entry->TypeIndex);

    TypeName = ObManagerGetNameByIndex(ConvertedTypeIndex);

    //Name
    RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
    lvitem.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
    lvitem.iSubItem = 0;
    lvitem.iItem = MAXINT;
    lvitem.iImage = ObManagerGetImageIndexByTypeIndex(ConvertedTypeIndex);
    lvitem.pszText = Entry->ObjectName;
    lvitem.lParam = (LPARAM)Entry;
    index = ListView_InsertItem(PnDlgContext.ListView, &lvitem);

    //Type
    lvitem.mask = LVIF_TEXT;
    lvitem.iSubItem = 1;
    lvitem.pszText = (LPWSTR)TypeName;
    lvitem.iItem = index;
    ListView_SetItem(PnDlgContext.ListView, &lvitem);

    //RootDirectory address
    lvitem.mask = LVIF_TEXT;
    lvitem.iSubItem = 2;
    _strcpy(szBuffer, TEXT("0x"));
    u64tohex(Entry->PrivateNamespace.NamespaceDirectoryAddress, _strend(szBuffer));
    lvitem.pszText = szBuffer;
    lvitem.iItem = index;
    ListView_SetItem(PnDlgContext.ListView, &lvitem);

    PNSNumberOfObjects++;

    return FALSE;
}

/*
* PNDlgQueryInfo
*
* Purpose:
*
* Query and ouput private namespaces info.
*
*/
BOOL PNDlgQueryInfo(
    _In_ HWND hwndDlg
)
{
    HWND hwndBanner;
    BOOL bResult = FALSE;

    PNSNumberOfObjects = 0;

    hwndBanner = supDisplayLoadBanner(
        hwndDlg,
        TEXT("Loading private namespaces information, please wait"));

    __try {

        bResult = ObCollectionCreate(&PNSCollection, TRUE, FALSE);
        if (bResult) {

            bResult = ObCollectionEnumerate(
                &PNSCollection,
                PNDlgEnumerateCallback,
                NULL);

        }
    }
    __finally {
        SendMessage(hwndBanner, WM_CLOSE, 0, 0);
    }

    return bResult;
}

#define MAX_LOOKUP_NAME 256

/*
* PNDlgOutputSelectedSidInformation
*
* Purpose:
*
* Output selected Sid information.
*
*/
VOID PNDlgOutputSelectedSidInformation(
    _In_ HWND hwndDlg,
    _In_opt_ PSID Sid
)
{
    BOOL bNeedFree = FALSE;
    HWND hComboBox;
    LRESULT nSelected;
    PSID pSid = NULL;
    LPWSTR SidType, SidValue;
    SIZE_T SidLength;

    DWORD cAccountName = 0, cReferencedDomainName = 0;

    WCHAR szName[MAX_LOOKUP_NAME];
    WCHAR szDomain[MAX_LOOKUP_NAME];
    WCHAR szAccountInfo[MAX_PATH * 3];

    EXT_SID_NAME_USE peUse;


    //
    // No SID specified, get current selection in combobox and use it as SID.
    //
    if (Sid == NULL) {
        hComboBox = GetDlgItem(hwndDlg, ID_BDESCRIPTOR_SID);

        nSelected = SendMessage(hComboBox, CB_GETCURSEL, (WPARAM)0, (LPARAM)0);
        if (nSelected != CB_ERR) {

            SidLength = SendMessage(hComboBox, CB_GETLBTEXTLEN, (WPARAM)nSelected, 0);
            if (SidLength) {

                SidValue = (LPWSTR)supHeapAlloc((1 + SidLength) * sizeof(WCHAR));
                if (SidValue) {

                    if (CB_ERR != SendMessage(hComboBox, CB_GETLBTEXT, nSelected, (LPARAM)SidValue)) {

                        if (ConvertStringSidToSid(SidValue, &pSid)) {
                            bNeedFree = TRUE;
                        }
                    }

                    supHeapFree(SidValue);
                }
            }
        }
    }
    else {
        pSid = Sid;
        bNeedFree = FALSE;
    }

    //
    // Convertion failure.
    //
    if (pSid == NULL)
        return;

    //
    // SID account domain\name (type).
    //
    RtlSecureZeroMemory(szName, sizeof(szName));
    RtlSecureZeroMemory(szDomain, sizeof(szDomain));
    cAccountName = MAX_LOOKUP_NAME;
    cReferencedDomainName = MAX_LOOKUP_NAME;

    if (LookupAccountSid(
        NULL,
        pSid,
        szName,
        &cAccountName,
        szDomain,
        &cReferencedDomainName,
        (SID_NAME_USE*)&peUse))
    {
        RtlSecureZeroMemory(szAccountInfo, sizeof(szAccountInfo));
        _strcpy(szAccountInfo, szDomain);
        if ((cAccountName) && (cReferencedDomainName)) {
            _strcat(szAccountInfo, TEXT("\\"));
        }
        _strcat(szAccountInfo, szName);

        //
        // Type of the account.
        //
        switch (peUse) {
        case ExtSidTypeUser:
            SidType = TEXT(" (SidUserType)");
            break;
        case ExtSidTypeGroup:
            SidType = TEXT(" (SidTypeGroup)");
            break;
        case ExtSidTypeDomain:
            SidType = TEXT(" (SidTypeDomain)");
            break;
        case ExtSidTypeAlias:
            SidType = TEXT(" (SidTypeAlias)");
            break;
        case ExtSidTypeWellKnownGroup:
            SidType = TEXT(" (SidTypeWellKnownGroup)");
            break;
        case ExtSidTypeDeletedAccount:
            SidType = TEXT(" (SidTypeDeletedAccount)");
            break;
        case ExtSidTypeInvalid:
            SidType = TEXT(" (SidTypeInvalid)");
            break;
        case ExtSidTypeComputer:
            SidType = TEXT(" (SidTypeComputer)");
            break;
        case ExtSidTypeLabel:
            SidType = TEXT(" (SidTypeLabel)");
            break;
        case ExtSidTypeLogonSession:
            SidType = TEXT(" (SidTypeLogonSession)");
            break;
        case ExtSidTypeUnknown:
        default:
            SidType = TEXT(" (SidTypeUnknown)");
            break;
        }

        _strcat(szAccountInfo, SidType);
    }
    else {
        _strcpy(szAccountInfo, T_CannotQuery);
    }
    SetDlgItemText(hwndDlg, ID_BDESCRIPTOR_SID_ACCOUNT, szAccountInfo);

    if (bNeedFree)
        LocalFree(pSid);
}

/*
* PNDlgBoundaryDescriptorCallback
*
* Purpose:
*
* Boundary descriptor enumerator callback.
*
*/
BOOL CALLBACK PNDlgBoundaryDescriptorCallback(
    _In_ OBJECT_BOUNDARY_ENTRY *Entry,
    _In_ PVOID Context
)
{
    PWSTR p, lpName;
    PSID Sid;
    HWND hwndDlg = (HWND)Context;
    DWORD dwIL;

    WCHAR szBuffer[MAX_PATH];

    switch (Entry->EntryType) {

    case OBNS_Name:

        p = (PWSTR)RtlOffsetToPointer(Entry, sizeof(OBJECT_BOUNDARY_ENTRY));
        lpName = (PWSTR)supHeapAlloc(Entry->EntrySize);
        if (lpName) {
            RtlCopyMemory(lpName, p, Entry->EntrySize - sizeof(OBJECT_BOUNDARY_ENTRY));
            SetDlgItemText(hwndDlg, ID_BDESCRIPTOR_NAME, lpName);
            supHeapFree(lpName);
        }
        break;

    case OBNS_SID:

        Sid = (PSID)RtlOffsetToPointer(Entry, sizeof(OBJECT_BOUNDARY_ENTRY));
        if (ConvertSidToStringSid(Sid, &p)) {
            SendMessage(GetDlgItem(hwndDlg, ID_BDESCRIPTOR_SID), CB_ADDSTRING, (WPARAM)0, (LPARAM)p);
            LocalFree(p);
        }

        PNDlgOutputSelectedSidInformation(hwndDlg, Sid);
        break;

    case OBNS_IntegrityLabel:

        Sid = (PSID)RtlOffsetToPointer(Entry, sizeof(OBJECT_BOUNDARY_ENTRY));

        dwIL = *RtlSubAuthoritySid(Sid,
            (DWORD)(UCHAR)(*RtlSubAuthorityCountSid(Sid) - 1));

        p = supIntegrityToString(dwIL);

        _strcpy(szBuffer, p);
        _strcat(szBuffer, L"(0x");
        ultohex(dwIL, _strend(szBuffer));
        _strcat(szBuffer, L")");

        SetDlgItemText(hwndDlg, ID_INTEGRITYLABEL, szBuffer);
        break;

    default:
        break;
    }
    return FALSE;
}

/*
* PNDlgShowNamespaceInfo
*
* Purpose:
*
* Display selected private namespace info.
*
*/
VOID PNDlgShowNamespaceInfo(
    _In_ HWND hwndDlg
)
{
    INT         nSelected;
    LPARAM      nSid;
    ULONG_PTR   BoundaryDescriptorAddress = 0;
    POBJREF     objRef = NULL;
    OBJREFPNS   pnsInfo;

    POBJECT_BOUNDARY_DESCRIPTOR BoundaryDescriptor = NULL;

    WCHAR szBuffer[64];

    if (ListView_GetSelectedCount(PnDlgContext.ListView) == 0) {
        return;
    }

    nSelected = ListView_GetSelectionMark(PnDlgContext.ListView);
    if (nSelected == -1) {
        return;
    }

    if (!supGetListViewItemParam(PnDlgContext.ListView, nSelected, (PVOID*)&objRef))
        return;

    if (objRef == NULL)
        return;

    RtlCopyMemory(&pnsInfo, &objRef->PrivateNamespace, sizeof(OBJREFPNS));

    //
    // Namespace root directory.
    //
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    szBuffer[0] = L'0';
    szBuffer[1] = L'x';
    u64tohex(pnsInfo.NamespaceDirectoryAddress, &szBuffer[2]);
    SetDlgItemText(hwndDlg, ID_NAMESPACE_ROOT, szBuffer);

    //
    // Namespace Lookup table entry.
    //
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    szBuffer[0] = L'0';
    szBuffer[1] = L'x';
    u64tohex(pnsInfo.NamespaceLookupEntry, &szBuffer[2]);
    SetDlgItemText(hwndDlg, ID_OBJECT_ADDR, szBuffer);

    //
    // SizeOfBoundaryInformation.
    //
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    szBuffer[0] = L'0';
    szBuffer[1] = L'x';
    ultohex(pnsInfo.SizeOfBoundaryInformation, &szBuffer[2]);
    SetDlgItemText(hwndDlg, ID_SIZEOFBOUNDARYINFO, szBuffer);

    //
    // Boundary Descriptor Address.
    //
    BoundaryDescriptorAddress = (ULONG_PTR)RtlOffsetToPointer(
        pnsInfo.NamespaceLookupEntry,
        sizeof(OBJECT_NAMESPACE_ENTRY));

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    szBuffer[0] = L'0';
    szBuffer[1] = L'x';
    u64tohex(BoundaryDescriptorAddress, &szBuffer[2]);
    SetDlgItemText(hwndDlg, ID_BDESCRIPTOR_ADDRESS, szBuffer);

    //
    // Reset output related controls.
    //
    SetDlgItemText(hwndDlg, ID_BDESCRIPTOR_NAME, TEXT(""));
    SetDlgItemText(hwndDlg, ID_BDESCRIPTOR_SID_ACCOUNT, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_INTEGRITYLABEL, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_BDESCRIPTOR_ENTRIES, TEXT("0"));
    SendDlgItemMessage(hwndDlg, ID_BDESCRIPTOR_SID, CB_RESETCONTENT, (WPARAM)0, (LPARAM)0);
    EnableWindow(GetDlgItem(hwndDlg, ID_BDESCRIPTOR_SID_COPY), FALSE);

    //
    // Boundary Descriptor Entries.
    //
    if (NT_SUCCESS(ObCopyBoundaryDescriptor(
        (OBJECT_NAMESPACE_ENTRY*)pnsInfo.NamespaceLookupEntry,
        &BoundaryDescriptor,
        NULL)))
    {
        //
        // Number of entries.
        //
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        ultostr(BoundaryDescriptor->Items, &szBuffer[0]);
        SetDlgItemText(hwndDlg, ID_BDESCRIPTOR_ENTRIES, szBuffer);

        ObEnumerateBoundaryDescriptorEntries(
            BoundaryDescriptor,
            PNDlgBoundaryDescriptorCallback,
            (PVOID)hwndDlg);

        //
        // Select first SID if present.
        //
        nSid = SendMessage(GetDlgItem(hwndDlg, ID_BDESCRIPTOR_SID), CB_GETCOUNT, 0, 0);

        EnableWindow(GetDlgItem(hwndDlg, ID_BDESCRIPTOR_SID), (nSid > 0) ? TRUE : FALSE);
        EnableWindow(GetDlgItem(hwndDlg, ID_BDESCRIPTOR_SID_COPY), (nSid > 0) ? TRUE : FALSE);

        SendMessage(GetDlgItem(hwndDlg, ID_BDESCRIPTOR_SID), CB_SETCURSEL, (WPARAM)0, (LPARAM)0);

        supHeapFree(BoundaryDescriptor);
    }
}

/*
* PNDlgHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for PNDialog listview.
*
*/
VOID PNDlgHandleNotify(
    _In_ HWND hwndDlg,
    _In_ LPNMLISTVIEW nhdr
)
{
    INT nImageIndex;

    if (nhdr == NULL)
        return;

    if (nhdr->hdr.idFrom == ID_NAMESPACELIST) {

        switch (nhdr->hdr.code) {

        case LVN_COLUMNCLICK:

            PnDlgContext.bInverseSort = !PnDlgContext.bInverseSort;
            PnDlgContext.lvColumnToSort = ((NMLISTVIEW *)nhdr)->iSubItem;
            ListView_SortItemsEx(PnDlgContext.ListView, &PNListCompareFunc, PnDlgContext.lvColumnToSort);

            nImageIndex = ImageList_GetImageCount(g_ListViewImages);
            if (PnDlgContext.bInverseSort)
                nImageIndex -= 2;
            else
                nImageIndex -= 1;

            supUpdateLvColumnHeaderImage(
                PnDlgContext.ListView,
                PnDlgContext.lvColumnCount,
                PnDlgContext.lvColumnToSort,
                nImageIndex);

            break;

        case LVN_ITEMCHANGED:
        case NM_CLICK:
            PNDlgShowNamespaceInfo(hwndDlg);
            break;

        case NM_DBLCLK:
            PNDlgShowObjectProperties();
            break;

        default:
            break;
        }
    }
}

/*
* PNDlgCopySelectedSid
*
* Purpose:
*
* Take selected sid entry and copy it as text to clipboard.
*
*/
VOID PNDlgCopySelectedSid(
    _In_ HWND hwndDlg
)
{
    HWND hComboBox = GetDlgItem(hwndDlg, ID_BDESCRIPTOR_SID);
    LPARAM nSelected = SendMessage(hComboBox, CB_GETCURSEL, 0, 0);
    LPARAM TextLength;
    PWCHAR lpStringSid;

    if (nSelected >= 0) {
        TextLength = SendMessage(hComboBox, CB_GETLBTEXTLEN, (WPARAM)nSelected, 0);
        if (TextLength) {
            lpStringSid = (PWCHAR)supHeapAlloc((1 + TextLength) * sizeof(WCHAR));
            if (lpStringSid) {
                SendMessage(hComboBox, CB_GETLBTEXT, nSelected, (LPARAM)lpStringSid);

                supClipboardCopy(lpStringSid, (TextLength * sizeof(WCHAR)));

                supHeapFree(lpStringSid);
            }
        }
    }
}

/*
* PNDialogShowInfo
*
* Purpose:
*
* Display information about private namespaces or message if there is none or error.
*
*/
VOID PNDialogShowInfo(
    _In_ BOOLEAN bRefresh)
{
    ENUMCHILDWNDDATA ChildWndData;

    if (bRefresh) {
        ListView_DeleteAllItems(PnDlgContext.ListView);
        ObCollectionDestroy(&PNSCollection);

        //
        // Reset output related controls.
        //
        SetDlgItemText(PnDlgContext.hwndDlg, ID_NAMESPACE_ROOT, TEXT(""));
        SetDlgItemText(PnDlgContext.hwndDlg, ID_OBJECT_ADDR, TEXT(""));
        SetDlgItemText(PnDlgContext.hwndDlg, ID_SIZEOFBOUNDARYINFO, TEXT(""));
        SetDlgItemText(PnDlgContext.hwndDlg, ID_BDESCRIPTOR_ADDRESS, TEXT(""));
        SetDlgItemText(PnDlgContext.hwndDlg, ID_BDESCRIPTOR_NAME, TEXT(""));
        SetDlgItemText(PnDlgContext.hwndDlg, ID_BDESCRIPTOR_SID_ACCOUNT, T_CannotQuery);
        SetDlgItemText(PnDlgContext.hwndDlg, ID_INTEGRITYLABEL, T_CannotQuery);
        SetDlgItemText(PnDlgContext.hwndDlg, ID_BDESCRIPTOR_ENTRIES, TEXT("0"));
        SendDlgItemMessage(PnDlgContext.hwndDlg, ID_BDESCRIPTOR_SID, CB_RESETCONTENT, (WPARAM)0, (LPARAM)0);
        EnableWindow(GetDlgItem(PnDlgContext.hwndDlg, ID_BDESCRIPTOR_SID_COPY), FALSE);
    }

    if (PNDlgQueryInfo(PnDlgContext.hwndDlg)) {
        ListView_SortItemsEx(PnDlgContext.ListView, &PNListCompareFunc, 0);
    }
    else {
        if (GetWindowRect(PnDlgContext.hwndDlg, &ChildWndData.Rect)) {
            ChildWndData.nCmdShow = SW_HIDE;
            EnumChildWindows(PnDlgContext.hwndDlg, supCallbackShowChildWindow, (LPARAM)&ChildWndData);
        }
        ShowWindow(GetDlgItem(PnDlgContext.hwndDlg, ID_PNAMESPACESINFO), SW_SHOW);

        if (PNSNumberOfObjects == 0) {
            SetDlgItemText(PnDlgContext.hwndDlg, ID_PNAMESPACESINFO, T_NAMESPACENOTHING);
        }
        else {
            SetDlgItemText(PnDlgContext.hwndDlg, ID_PNAMESPACESINFO, T_NAMESPACEQUERYFAILED);
        }
    }
}

/*
* PNDialogProc
*
* Purpose:
*
* Private Namespace Dialog window procedure.
*
*/
INT_PTR CALLBACK PNDialogProc(
    _In_  HWND hwndDlg,
    _In_  UINT uMsg,
    _In_  WPARAM wParam,
    _In_  LPARAM lParam
)
{
    LPNMLISTVIEW nhdr = (LPNMLISTVIEW)lParam;

    switch (uMsg) {
    case WM_NOTIFY:
        PNDlgHandleNotify(hwndDlg, nhdr);
        break;

    case WM_INITDIALOG:
        supCenterWindow(hwndDlg);
        break;

    case WM_CLOSE:
        DestroyWindow(hwndDlg);
        ObCollectionDestroy(&PNSCollection);
        g_WinObj.AuxDialogs[wobjPNSDlgId] = NULL;
        return TRUE;

    case WM_COMMAND:

        switch (LOWORD(wParam)) {

        case IDCANCEL:
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            return TRUE;

        case ID_VIEW_REFRESH:
            PNDialogShowInfo(TRUE);
            break;

        case ID_BDESCRIPTOR_SID:
            if (HIWORD(wParam) == CBN_SELCHANGE) {
                PNDlgOutputSelectedSidInformation(hwndDlg, NULL);
                return TRUE;
            }
            break;

        case ID_BDESCRIPTOR_SID_COPY: //copy selected sid value to clipboard
            PNDlgCopySelectedSid(hwndDlg);
            break;

        default:
            break;
        }

        break;
    }
    return FALSE;
}

/*
* extrasCreatePNDialog
*
* Purpose:
*
* Create and initialize Private Namespaces Dialog.
*
*/
VOID extrasCreatePNDialog(
    _In_ HWND hwndParent
)
{
    LVCOLUMN col;

    //allow only one dialog
    if (g_WinObj.AuxDialogs[wobjPNSDlgId]) {
        SetActiveWindow(g_WinObj.AuxDialogs[wobjPNSDlgId]);
        return;
    }

    RtlSecureZeroMemory(&PnDlgContext, sizeof(PnDlgContext));
    PnDlgContext.hwndDlg = CreateDialogParam(g_WinObj.hInstance, MAKEINTRESOURCE(IDD_DIALOG_PNAMESPACE),
        hwndParent, &PNDialogProc, 0);

    if (PnDlgContext.hwndDlg == NULL) {
        return;
    }

    RtlSecureZeroMemory(&PNSCollection, sizeof(OBJECT_COLLECTION));

    g_WinObj.AuxDialogs[wobjPNSDlgId] = PnDlgContext.hwndDlg;

    PnDlgContext.ListView = GetDlgItem(PnDlgContext.hwndDlg, ID_NAMESPACELIST);
    if (PnDlgContext.ListView) {

        //
        // Set listview imagelist, style flags and theme.
        //
        ListView_SetImageList(PnDlgContext.ListView, g_ListViewImages, LVSIL_SMALL);
        ListView_SetExtendedListViewStyle(
            PnDlgContext.ListView,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

        SetWindowTheme(PnDlgContext.ListView, TEXT("Explorer"), NULL);

        //
        // Create ListView columns.
        //
        RtlSecureZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER | LVCF_IMAGE;
        col.iSubItem++;
        col.pszText = TEXT("Name");
        col.fmt = LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT;
        col.iImage = ImageList_GetImageCount(g_ListViewImages) - 1;
        col.cx = 280;
        ListView_InsertColumn(PnDlgContext.ListView, col.iSubItem, &col);

        col.iImage = I_IMAGENONE;

        col.iSubItem++;
        col.pszText = TEXT("Type");
        col.iOrder = 1;
        col.cx = 100;
        ListView_InsertColumn(PnDlgContext.ListView, col.iSubItem, &col);

        col.iSubItem++;
        col.pszText = TEXT("RootDirectory");
        col.iOrder = 2;
        col.cx = 140;
        ListView_InsertColumn(PnDlgContext.ListView, col.iSubItem, &col);

        //remember columns count
        PnDlgContext.lvColumnCount = col.iSubItem;

        //initial call, nothing to refresh
        PNDialogShowInfo(FALSE);
    }
}
