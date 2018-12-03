/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       EXTRASPN.C
*
*  VERSION:     1.60
*
*  DATE:        24 Oct 2018
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

EXTRASCONTEXT DlgContext;
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
    _In_ HWND ParentWindow
)
{
    INT                 nSelected;
    LPWSTR              lpType, lpName;
    POBJREF             objRef;

    OBJREFPNS           pnsInfo;
    PROP_NAMESPACE_INFO propNamespace;
    LVITEM              lvitem;

    if (g_NamespacePropWindow != NULL)
        return;

    if (ListView_GetSelectedCount(DlgContext.ListView) == 0) {
        return;
    }

    nSelected = ListView_GetSelectionMark(DlgContext.ListView);
    if (nSelected == -1) {
        return;
    }

    //
    //  Get ref to object, failure here is critical.
    //
    RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
    lvitem.mask = LVIF_PARAM;
    lvitem.iItem = nSelected;

    ListView_GetItem(DlgContext.ListView, &lvitem);

    objRef = (OBJREF*)lvitem.lParam;
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

    lpName = supGetItemText(DlgContext.ListView, nSelected, 0, NULL);
    if (lpName) {
        lpType = supGetItemText(DlgContext.ListView, nSelected, 1, NULL);
        if (lpType) {

            propCreateDialog(
                ParentWindow,
                lpName,
                lpType,
                NULL,
                &propNamespace);

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
            DlgContext.ListView,
            lParam1,
            lParam2,
            lParamSort,
            DlgContext.bInverseSort);
    }

    lpItem1 = supGetItemText(DlgContext.ListView, (INT)lParam1, (INT)lParamSort, NULL);
    lpItem2 = supGetItemText(DlgContext.ListView, (INT)lParam2, (INT)lParamSort, NULL);

    if ((lpItem1 == NULL) && (lpItem2 == NULL)) {
        nResult = 0;
        goto Done;
    }
    if ((lpItem1 == NULL) && (lpItem2 != NULL)) {
        nResult = (DlgContext.bInverseSort) ? 1 : -1;
        goto Done;
    }
    if ((lpItem2 == NULL) && (lpItem1 != NULL)) {
        nResult = (DlgContext.bInverseSort) ? -1 : 1;
        goto Done;
    }

    if (DlgContext.bInverseSort)
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
    _In_ PVOID Context
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

    TypeName = g_ObjectTypes[ConvertedTypeIndex].Name;

    //Name
    RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
    lvitem.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
    lvitem.iSubItem = 0;
    lvitem.iItem = MAXINT;
    lvitem.iImage = ConvertedTypeIndex;
    lvitem.pszText = Entry->ObjectName;
    lvitem.lParam = (LPARAM)Entry;
    index = ListView_InsertItem(DlgContext.ListView, &lvitem);

    //Type
    lvitem.mask = LVIF_TEXT;
    lvitem.iSubItem = 1;
    lvitem.pszText = (LPWSTR)TypeName;
    lvitem.iItem = index;
    ListView_SetItem(DlgContext.ListView, &lvitem);

    //RootDirectory address
    lvitem.mask = LVIF_TEXT;
    lvitem.iSubItem = 2;
    _strcpy(szBuffer, TEXT("0x"));
    u64tohex(Entry->PrivateNamespace.NamespaceDirectoryAddress, _strend(szBuffer));
    lvitem.pszText = szBuffer;
    lvitem.iItem = index;
    ListView_SetItem(DlgContext.ListView, &lvitem);

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
    VOID
)
{
    BOOL bResult = FALSE;

    PNSNumberOfObjects = 0;

    bResult = ObCollectionCreate(&PNSCollection, TRUE, FALSE);
    if (bResult) {

        bResult = ObCollectionEnumerate(
            &PNSCollection,
            PNDlgEnumerateCallback,
            NULL);

    }
    return bResult;
}

/*
* PNDlgIL2Text
*
* Purpose:
*
* Translate Integrity Level to name.
*
*/
LPWSTR PNDlgIL2Text(
    _In_ DWORD dwIL
)
{
    LPWSTR lpValue = L"UnknownIL";

    if (dwIL == SECURITY_MANDATORY_UNTRUSTED_RID) {
        lpValue = L"UntrustedIL";
    }
    else if (dwIL == SECURITY_MANDATORY_LOW_RID) {
        lpValue = L"LowIL";
    }
    else if (dwIL >= SECURITY_MANDATORY_MEDIUM_RID &&
        dwIL < SECURITY_MANDATORY_HIGH_RID)
    {
        lpValue = L"MediumIL";
    }
    else if (dwIL >= SECURITY_MANDATORY_HIGH_RID &&
        dwIL < SECURITY_MANDATORY_SYSTEM_RID)
    {
        lpValue = L"HighIL";
    }
    else if (dwIL >= SECURITY_MANDATORY_SYSTEM_RID &&
        dwIL < SECURITY_MANDATORY_PROTECTED_PROCESS_RID)
    {
        lpValue = L"SystemIL";
    }
    else if (dwIL >= SECURITY_MANDATORY_PROTECTED_PROCESS_RID)
    {
        lpValue = L"ProtectedProcessIL";
    }

    return lpValue;
}

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
    PSID pSid;
    PWSTR stype;

    DWORD cAccountName, cReferencedDomainName;

    WCHAR szName[256];
    WCHAR szDomain[256];
    WCHAR szAccountInfo[MAX_PATH * 3];

    SID_NAME_USE peUse;

    WCHAR szSid[MAX_PATH * 2];

    //
    // Not SID specified, get current selection in combobox and use it as SID.
    //
    if (Sid == NULL) {
        hComboBox = GetDlgItem(hwndDlg, ID_BDESCRIPTOR_SID);

        nSelected = SendMessage(hComboBox, CB_GETCURSEL, (WPARAM)0, (LPARAM)0);

        RtlSecureZeroMemory(szSid, sizeof(szSid));
        SendMessage(hComboBox, CB_GETLBTEXT, nSelected, (LPARAM)&szSid);

        if (ConvertStringSidToSid(szSid, &pSid)) {
            bNeedFree = TRUE;
        }
        else {
            return;
        }
    }
    else {
        pSid = Sid;
        bNeedFree = FALSE;
    }

    //
   // SID account domain\name (type).
   //
    if (LookupAccountSid(
        NULL,
        pSid,
        szName,
        &cAccountName,
        szDomain,
        &cReferencedDomainName,
        &peUse))
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
        case SidTypeUser:
            stype = TEXT(" (SidUserType)");
            break;
        case SidTypeGroup:
            stype = TEXT(" (SidTypeGroup)");
            break;
        case SidTypeDomain:
            stype = TEXT(" (SidTypeDomain)");
            break;
        case SidTypeAlias:
            stype = TEXT(" (SidTypeAlias)");
            break;
        case SidTypeWellKnownGroup:
            stype = TEXT(" (SidTypeWellKnownGroup)");
            break;
        case SidTypeDeletedAccount:
            stype = TEXT(" (SidTypeDeletedAccount)");
            break;
        case SidTypeInvalid:
            stype = TEXT(" (SidTypeInvalid)");
            break;
        case SidTypeComputer:
            stype = TEXT(" (SidTypeComputer)");
            break;
        case SidTypeLabel:
            stype = TEXT(" (SidTypeLabel)");
            break;
        case 11: //SidTypeLogonSession
            stype = TEXT(" (SidTypeLogonSession)");
            break;
        case SidTypeUnknown:
        default:
            stype = TEXT(" (SidTypeUnknown)");
            break;
        }

        _strcat(szAccountInfo, stype);
    }
    else {
        _strcpy(szAccountInfo, TEXT("-"));
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
    HANDLE hwndDlg = (HWND)Context;
    DWORD dwIL;

    WCHAR szBuffer[MAX_PATH];

    switch (Entry->EntryType) {

    case OBNS_Name:

        p = (PWSTR)RtlOffsetToPointer(Entry, sizeof(OBJECT_BOUNDARY_ENTRY));
        lpName = supHeapAlloc(Entry->EntrySize);
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

        p = PNDlgIL2Text(dwIL);

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
    POBJREF     objRef;
    OBJREFPNS   pnsInfo;
    LVITEM      lvitem;

    POBJECT_BOUNDARY_DESCRIPTOR BoundaryDescriptor = NULL;

    WCHAR szBuffer[64];

    if (ListView_GetSelectedCount(DlgContext.ListView) == 0) {
        return;
    }

    nSelected = ListView_GetSelectionMark(DlgContext.ListView);
    if (nSelected == -1) {
        return;
    }

    RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
    lvitem.mask = LVIF_PARAM;
    lvitem.iItem = nSelected;

    ListView_GetItem(DlgContext.ListView, &lvitem);

    objRef = (OBJREF*)lvitem.lParam;
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
    SetDlgItemText(hwndDlg, ID_BDESCRIPTOR_NAME, NULL);
    SetDlgItemText(hwndDlg, ID_BDESCRIPTOR_SID_ACCOUNT, TEXT("-"));
    SetDlgItemText(hwndDlg, ID_INTEGRITYLABEL, TEXT("-"));
    SetDlgItemText(hwndDlg, ID_BDESCRIPTOR_ENTRIES, TEXT("0"));
    SendMessage(GetDlgItem(hwndDlg, ID_BDESCRIPTOR_SID), CB_RESETCONTENT, (WPARAM)0, (LPARAM)0);
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

            DlgContext.bInverseSort = !DlgContext.bInverseSort;
            DlgContext.lvColumnToSort = ((NMLISTVIEW *)nhdr)->iSubItem;
            ListView_SortItemsEx(DlgContext.ListView, &PNListCompareFunc, DlgContext.lvColumnToSort);

            nImageIndex = ImageList_GetImageCount(g_ListViewImages);
            if (DlgContext.bInverseSort)
                nImageIndex -= 2;
            else
                nImageIndex -= 1;

            supUpdateLvColumnHeaderImage(
                DlgContext.ListView,
                DlgContext.lvColumnCount,
                DlgContext.lvColumnToSort,
                nImageIndex);

            break;

        case LVN_ITEMCHANGED:
        case NM_CLICK:
            PNDlgShowNamespaceInfo(hwndDlg);
            break;

        case NM_DBLCLK:
            PNDlgShowObjectProperties(hwndDlg);
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
            lpStringSid = supHeapAlloc((1 + TextLength) * sizeof(WCHAR));
            if (lpStringSid) {
                SendMessage(hComboBox, CB_GETLBTEXT, nSelected, (LPARAM)lpStringSid);

                supClipboardCopy(lpStringSid, (TextLength * sizeof(WCHAR)));

                supHeapFree(lpStringSid);
            }
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
        g_WinObj.AuxDialogs[WOBJ_PNDLG_IDX] = NULL;
        return TRUE;

    case WM_COMMAND:

        switch (LOWORD(wParam)) {

        case IDCANCEL:
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            return TRUE;

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
    RECT     rGB;
    LVCOLUMN col;

    //allow only one dialog
    if (g_WinObj.AuxDialogs[WOBJ_PNDLG_IDX]) {
        SetActiveWindow(g_WinObj.AuxDialogs[WOBJ_PNDLG_IDX]);
        return;
    }

    RtlSecureZeroMemory(&DlgContext, sizeof(DlgContext));
    DlgContext.hwndDlg = CreateDialogParam(g_WinObj.hInstance, MAKEINTRESOURCE(IDD_DIALOG_PNAMESPACE),
        hwndParent, &PNDialogProc, 0);

    if (DlgContext.hwndDlg == NULL) {
        return;
    }

    RtlSecureZeroMemory(&PNSCollection, sizeof(OBJECT_COLLECTION));

    g_WinObj.AuxDialogs[WOBJ_PNDLG_IDX] = DlgContext.hwndDlg;

    DlgContext.ListView = GetDlgItem(DlgContext.hwndDlg, ID_NAMESPACELIST);
    if (DlgContext.ListView) {

        //
        // Set listview imagelist, style flags and theme.
        //
        ListView_SetImageList(DlgContext.ListView, g_ListViewImages, LVSIL_SMALL);
        ListView_SetExtendedListViewStyle(
            DlgContext.ListView,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

        SetWindowTheme(DlgContext.ListView, TEXT("Explorer"), NULL);

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
        ListView_InsertColumn(DlgContext.ListView, col.iSubItem, &col);

        col.iImage = I_IMAGENONE;

        col.iSubItem++;
        col.pszText = TEXT("Type");
        col.iOrder = 1;
        col.cx = 100;
        ListView_InsertColumn(DlgContext.ListView, col.iSubItem, &col);

        col.iSubItem++;
        col.pszText = TEXT("RootDirectory");
        col.iOrder = 2;
        col.cx = 140;
        ListView_InsertColumn(DlgContext.ListView, col.iSubItem, &col);

        //remember columns count
        DlgContext.lvColumnCount = col.iSubItem;

        if (PNDlgQueryInfo()) {
            ListView_SortItemsEx(DlgContext.ListView, &PNListCompareFunc, 0);
        }
        else {
            if (GetWindowRect(DlgContext.hwndDlg, &rGB)) {
                EnumChildWindows(DlgContext.hwndDlg, supEnumHideChildWindows, (LPARAM)&rGB);
            }
            ShowWindow(GetDlgItem(DlgContext.hwndDlg, ID_PNAMESPACESINFO), SW_SHOW);

            if (PNSNumberOfObjects == 0) {
                SetDlgItemText(DlgContext.hwndDlg, ID_PNAMESPACESINFO, T_NAMESPACENOTHING);
            }
            else {
                SetDlgItemText(DlgContext.hwndDlg, ID_PNAMESPACESINFO, T_NAMESPACEQUERYFAILED);
            }
        }
    }
}
