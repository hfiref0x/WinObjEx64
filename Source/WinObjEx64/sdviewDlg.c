/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       SDVIEWDLG.C
*
*  VERSION:     1.90
*
*  DATE:        11 May 2021
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "sdviewDlg.h"

#define SDVIEWDLG_TRACKSIZE_MIN_X 480
#define SDVIEWDLG_TRACKSIZE_MIN_Y 320

//
// SDView Dialog context structure.
//

typedef struct _SDVIEW_CONTEXT {
    //
    // Dialog controls and resources.
    //
    HWND DialogWindow;
    HWND StatusBar;
    HWND AceList;
    HICON DialogIcon;

    //
    // Viewed object data.
    //
    LPWSTR Directory;
    LPWSTR Name;
    WOBJ_OBJECT_TYPE Type;

    //
    // ListView selection.
    //
    INT iSelectedItem;
    INT iColumnHit;

    //
    // Window controls layout.
    //
    RECT WindowRect;
    RECT ListRect;
    RECT ButtonRect;
} SDVIEW_CONTEXT, * PSDVIEW_CONTEXT;

//
// Ace list dump callback data structure.
//

typedef struct _ACE_DUMP_ENTRY {
    _In_ LPWSTR lpAceType;
    _In_ LPWSTR lpAceFlags;
    _In_ LPWSTR lpAccessMask;
    _In_opt_ LPWSTR lpDomain;
    _In_opt_ LPWSTR lpName;
    _In_ LPWSTR lpSidNameUse;
    _In_ PUNICODE_STRING SidString;
} ACE_DUMP_ENTRY, * PACE_DUMP_ENTRY;

typedef VOID(CALLBACK* pfnSidOutputCallback)(
    _In_ SDVIEW_CONTEXT* Context,
    _In_ LPWSTR Information,
    _In_opt_ PVOID CallbackContext
    );

typedef VOID(CALLBACK* pfnAceOutputCallback)(
    _In_ SDVIEW_CONTEXT* Context,
    _In_ PACE_DUMP_ENTRY Entry,
    _In_opt_ PVOID CallbackContext
    );

/*
* FreeSDViewContext
*
* Purpose:
*
* Free memory allocated for per-dialog context structure.
*
*/
VOID FreeSDViewContext(
    _In_ SDVIEW_CONTEXT* SdViewContext
)
{
    if (SdViewContext->Name)
        supHeapFree(SdViewContext->Name);
    if (SdViewContext->Directory)
        supHeapFree(SdViewContext->Directory);

    supHeapFree(SdViewContext);
}

/*
* AllocateSDViewContext
*
* Purpose:
*
* Allocate memory for per-dialog context structure and fill it.
*
*/
SDVIEW_CONTEXT* AllocateSDViewContext(
    _In_ LPWSTR ObjectDirectory,
    _In_opt_ LPWSTR ObjectName,
    _In_ WOBJ_OBJECT_TYPE ObjectType
)
{
    SDVIEW_CONTEXT* ctx;
    SIZE_T nLen, nNameLen = 0;

    nLen = _strlen(ObjectDirectory);
    if (nLen == 0)
        return NULL;

    if (ObjectName) {
        nNameLen = _strlen(ObjectName);
        if (nNameLen == 0)
            return NULL;
    }

    ctx = (SDVIEW_CONTEXT*)supHeapAlloc(sizeof(SDVIEW_CONTEXT));
    if (ctx == NULL)
        return NULL;

    ctx->Directory = (LPWSTR)supHeapAlloc((1 + nLen) * sizeof(WCHAR));
    if (ctx->Directory == NULL) {
        FreeSDViewContext(ctx);
        return NULL;
    }

    _strcpy(ctx->Directory, ObjectDirectory);

    ctx->Type = ObjectType;

    if (ObjectName) {

        ctx->Name = (LPWSTR)supHeapAlloc((1 + nNameLen) * sizeof(WCHAR));
        if (ctx->Name == NULL) {
            FreeSDViewContext(ctx);
            return NULL;
        }

        _strcpy(ctx->Name, ObjectName);
    }

    return ctx;
}

/*
* OutputSidCallback
*
* Purpose:
*
* Output SID information callback.
*
*/
VOID CALLBACK OutputSidCallback(
    _In_ SDVIEW_CONTEXT* Context,
    _In_ LPWSTR SidInformation,
    _In_opt_ PVOID CallbackContext
)
{
    UNREFERENCED_PARAMETER(CallbackContext);

    SetDlgItemText(Context->DialogWindow, IDC_SDVIEW_OWNER, SidInformation);
}

/*
* OutputAclEntryCallback
*
* Purpose:
*
* Output ACL entry information callback.
*
*/
VOID CALLBACK OutputAclEntryCallback(
    _In_ SDVIEW_CONTEXT* Context,
    _In_ PACE_DUMP_ENTRY Entry,
    _In_ PVOID CallbackContext
)
{
    INT lvItemIndex;
    HWND hwndList = Context->AceList;

    LVITEM lvItem;
    WCHAR szBuffer[1040];


    RtlSecureZeroMemory(&lvItem, sizeof(lvItem));

    //
    // Ace type.
    //
    lvItem.mask = LVIF_TEXT | LVIF_GROUPID;
    lvItem.iItem = MAXINT;
    lvItem.iImage = I_IMAGENONE;
    lvItem.iGroupId = PtrToInt(CallbackContext);
    lvItem.pszText = Entry->lpAceType;
    lvItem.cchTextMax = (INT)_strlen(lvItem.pszText);
    lvItemIndex = ListView_InsertItem(hwndList, &lvItem);

    lvItem.mask = LVIF_TEXT;

    //
    // Ace flags.
    //
    lvItem.pszText = Entry->lpAceFlags;
    lvItem.cchTextMax = (INT)_strlen(lvItem.pszText);
    lvItem.iItem = lvItemIndex;
    ++lvItem.iSubItem;
    ListView_SetItem(hwndList, &lvItem);

    //
    // Acess mask.
    //
    lvItem.pszText = Entry->lpAccessMask;
    lvItem.cchTextMax = (INT)_strlen(lvItem.pszText);
    ++lvItem.iSubItem;
    ListView_SetItem(hwndList, &lvItem);

    //
    // SID.
    //
    RtlStringCchPrintfSecure(szBuffer,
        RTL_NUMBER_OF(szBuffer),
        L"%wZ",
        Entry->SidString);

    lvItem.pszText = szBuffer;
    lvItem.cchTextMax = (INT)_strlen(szBuffer);
    ++lvItem.iSubItem;
    ListView_SetItem(hwndList, &lvItem);

    //
    // Domain and Name
    //
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    if (Entry->lpDomain) {
        _strcpy(szBuffer, Entry->lpDomain);
        if (Entry->lpName) {
            _strcat(szBuffer, TEXT("\\"));
            _strcat(szBuffer, Entry->lpName);
        }
    }
    else {
        if (Entry->lpName)
            _strcpy(szBuffer, Entry->lpName);
        else
            _strcpy(szBuffer, T_NotAssigned);
    }

    lvItem.pszText = szBuffer;
    lvItem.cchTextMax = (INT)_strlen(szBuffer);
    ++lvItem.iSubItem;
    ListView_SetItem(hwndList, &lvItem);

    //
    // Alias.
    //
    lvItem.pszText = Entry->lpSidNameUse;
    lvItem.cchTextMax = (INT)_strlen(lvItem.pszText);
    ++lvItem.iSubItem;
    ListView_SetItem(hwndList, &lvItem);
}

/*
* SDViewUpdateStatusBar
*
* Purpose:
*
* Set dialog status bar text.
*
*/
VOID SDViewUpdateStatusBar(
    _In_ SDVIEW_CONTEXT* Context,
    ULONG DaclCount,
    ULONG SaclCount
)
{
    WCHAR szBuffer[100];

    RtlStringCchPrintfSecure(szBuffer,
        RTL_NUMBER_OF(szBuffer),
        L"DACL Entries: %lu, SACL Entries: %lu",
        DaclCount,
        SaclCount);

    supStatusBarSetText(Context->StatusBar, 0, szBuffer);
}

/*
* SDViewDumpAceList
*
* Purpose:
*
* Output ACE list members.
*
*/
ULONG SDViewDumpAceList(
    _In_ SDVIEW_CONTEXT* Context,
    _In_ ULONG AceCount,
    _In_ PVOID FirstAce,
    _In_ LSA_HANDLE PolicyHandle,
    _In_ pfnAceOutputCallback OutputCallback,
    _In_ PVOID CallbackContext
)
{
    ULONG domainIndex, nCount, domainsEntries = 0, totalEntries = 0;
    NTSTATUS ntStatus;
    BOOL bDomainNamePresent = FALSE, bNamePresent = FALSE;

    PLSA_TRANSLATED_NAME translatedNames = NULL, pNames = NULL;
    PLSA_REFERENCED_DOMAIN_LIST referencedDomains = NULL;
    PUNICODE_STRING pusDomainName, pusName;
    PSID* lookupSids;
    PSID aceSid;
    ULONG sidCount = 0;
    ACCESS_MASK accessMask;

    UNICODE_STRING stringSid, usEmpty;

    SID_NAME_USE sidNameUse;

    WCHAR szDomain[512], szName[512];
    WCHAR szAccessMask[32], szAceType[32], szAceFlags[32];
    LPWSTR lpAceType;

    ACE_DUMP_ENTRY dumpData;

    union {
        PBYTE ListRef;
        PACE_HEADER Header;
        PACCESS_ALLOWED_ACE AccessAllowed;
    } aceList;

    aceList.ListRef = (PBYTE)FirstAce;

    //
    // Allocate array of sids for LsaLookupSids.
    //
    lookupSids = (PSID*)supHeapAlloc(AceCount * sizeof(PSID));
    if (lookupSids == NULL)
        return 0;

    __try {

        //
        // Fill sids array for LsaLookupSids.
        //
        nCount = AceCount;

        do {

            aceSid = supGetSidFromAce(aceList.Header);

            if (RtlValidSid(aceSid)) {
                lookupSids[sidCount++] = aceSid;
            }

            aceList.ListRef += aceList.Header->AceSize;

        } while (--nCount);

        //
        // Lookup sids.
        //
        ntStatus = LsaLookupSids(PolicyHandle,
            sidCount,
            lookupSids,
            &referencedDomains,
            &translatedNames);

        if (NT_SUCCESS(ntStatus)) {

            pNames = translatedNames;
            domainsEntries = referencedDomains->Entries;

        }

        aceList.ListRef = (PBYTE)FirstAce;
        nCount = AceCount;

        RtlInitEmptyUnicodeString(&stringSid, NULL, 0);
        RtlInitEmptyUnicodeString(&usEmpty, NULL, 0);

        //
        // List aces.
        //

        do {

            aceSid = supGetSidFromAce(aceList.Header);
            if (!RtlValidSid(aceSid)) {
                continue;
            }

            //
            // Convert SID to string, on failure zero result so RtlFreeUnicodeString won't fuckup.
            //
            if (!NT_SUCCESS(RtlConvertSidToUnicodeString(&stringSid,
                aceSid,
                TRUE)))
            {
                stringSid.Buffer = NULL;
                stringSid.Length = 0;
            }

            sidNameUse = SidTypeUnknown;
            pusDomainName = &usEmpty;
            pusName = &usEmpty;

            //
            // Link domain, name and sid name use.
            //

            if (pNames) {

                domainIndex = pNames->DomainIndex;
                if (domainIndex < domainsEntries)
                    pusDomainName = &referencedDomains->Domains[domainIndex].Name;

                pusName = &pNames->Name;
                sidNameUse = pNames->Use;
                pNames++;

            }

            bDomainNamePresent = (pusDomainName->Length > 0);
            bNamePresent = (pusName->Length > 0);

            accessMask = aceList.AccessAllowed->Mask;

            szAccessMask[0] = L'0';
            szAccessMask[1] = L'x';
            szAccessMask[2] = 0;
            ultohex((ULONG)accessMask, &szAccessMask[2]);

            szAceFlags[0] = L'0';
            szAceFlags[1] = L'x';
            szAceFlags[2] = 0;
            ultohex((ULONG)aceList.Header->AceFlags, &szAceFlags[2]);

            switch (aceList.Header->AceType) {

            case ACCESS_ALLOWED_ACE_TYPE:
                lpAceType = L"AccessAllowed";
                break;

            case ACCESS_DENIED_ACE_TYPE:
                lpAceType = L"AccessDenied";
                break;

            case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
                lpAceType = L"Mandatory";
                szAccessMask[0] = accessMask & SYSTEM_MANDATORY_LABEL_NO_READ_UP ? L'R' : L'-';
                szAccessMask[1] = accessMask & SYSTEM_MANDATORY_LABEL_NO_WRITE_UP ? L'W' : L'-';
                szAccessMask[2] = accessMask & SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP ? L'E' : L'-';
                szAccessMask[3] = 0;
                break;

            case SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE:
                lpAceType = L"TrustLabel";
                break;

            case SYSTEM_ACCESS_FILTER_ACE_TYPE:
                lpAceType = L"AccessFilter";
                break;

            default:
                //
                // Irrelevant, report as is.
                //
                szAceType[0] = L'0';
                szAceType[1] = L'x';
                szAceType[2] = 0;
                ultohex((ULONG)aceList.Header->AceType, &szAceType[2]);
                lpAceType = (LPWSTR)&szAceType;
                break;
            }

            //
            // Domain and name.
            //
            RtlSecureZeroMemory(&szDomain, sizeof(szDomain));
            szDomain[0] = 0;
            RtlSecureZeroMemory(&szName, sizeof(szName));
            szName[0] = 0;

            switch (sidNameUse) {
            case SidTypeInvalid:
            case SidTypeUnknown:
                //
                // Invalid or unknown, skip domain and name.
                //
                break;

            default:

                if (bNamePresent) {

                    RtlStringCchPrintfSecure(szName,
                        RTL_NUMBER_OF(szName),
                        L"%wZ",
                        pusName);

                }

                if (bDomainNamePresent) {

                    RtlStringCchPrintfSecure(szDomain,
                        RTL_NUMBER_OF(szDomain),
                        L"%wZ",
                        pusDomainName);

                }

                break;
            }

            dumpData.lpAccessMask = szAccessMask;
            dumpData.lpAceFlags = szAceFlags;
            dumpData.lpAceType = lpAceType;
            dumpData.lpDomain = bDomainNamePresent ? szDomain : NULL;
            dumpData.lpName = bNamePresent ? szName : NULL;
            dumpData.lpSidNameUse = supGetSidNameUse(sidNameUse);
            dumpData.SidString = &stringSid;

            OutputCallback(Context, &dumpData, CallbackContext);
            totalEntries++;

            RtlFreeUnicodeString(&stringSid);

        } while (aceList.ListRef += aceList.Header->AceSize, --nCount);

    }
    __finally {
        supHeapFree(lookupSids);
        if (referencedDomains) LsaFreeMemory(referencedDomains);
        if (translatedNames) LsaFreeMemory(translatedNames);
    }

    return totalEntries;
}

/*
* SDViewDumpAcl
*
* Purpose:
*
* Output ACL information.
*
*/
ULONG SDViewDumpAcl(
    _In_ SDVIEW_CONTEXT* Context,
    _In_opt_ PACL Acl,
    _In_ LSA_HANDLE PolicyHandle,
    _In_ pfnAceOutputCallback OutputCallback,
    _In_ PVOID CallbackContext
)
{
    PVOID firstAce = NULL;

    if (Acl == NULL) {
        return 0;
    }

    if (Acl->AceCount == 0) {
        return 0;
    }

    if (NT_SUCCESS(RtlGetAce(Acl, 0, &firstAce))) {

        return SDViewDumpAceList(Context,
            Acl->AceCount,
            firstAce,
            PolicyHandle,
            OutputCallback,
            CallbackContext);

    }

    return 0;
}

/*
* SDViewDumpSid
*
* Purpose:
*
* Output SID information.
*
*/
VOID SDViewDumpSid(
    _In_ SDVIEW_CONTEXT* Context,
    _In_ PSID Sid,
    _In_ LSA_HANDLE PolicyHandle,
    _In_ pfnSidOutputCallback OutputCallback,
    _In_opt_ PVOID CallbackContext
)
{
    ULONG domainIndex, domainsEntries;
    NTSTATUS ntStatus;
    PLSA_TRANSLATED_NAME translatedNames = NULL, pNames;
    PLSA_REFERENCED_DOMAIN_LIST referencedDomains = NULL;
    PUNICODE_STRING pusDomainName, pusName;
    LPWSTR pSidNameUseString = NULL;

    UNICODE_STRING stringSid, usEmpty;

    SID_NAME_USE sidNameUse;

    WCHAR szBuffer[1024];

    //
    // Do we have anything to show?
    //
    if (!RtlValidSid(Sid))
        return;

    __try {

        pNames = NULL;
        domainsEntries = 0;

        ntStatus = LsaLookupSids(PolicyHandle,
            1,
            &Sid,
            &referencedDomains,
            &translatedNames);

        if (NT_SUCCESS(ntStatus)) {
            pNames = translatedNames;
            domainsEntries = referencedDomains->Entries;
        }

        RtlInitEmptyUnicodeString(&stringSid, NULL, 0);
        RtlInitEmptyUnicodeString(&usEmpty, NULL, 0);

        //
        // Convert SID to string, on failure zero result so RtlFreeUnicodeString won't fuckup.
        //
        if (!NT_SUCCESS(RtlConvertSidToUnicodeString(&stringSid,
            Sid,
            TRUE)))
        {
            stringSid.Buffer = NULL;
            stringSid.Length = 0;
        }

        sidNameUse = SidTypeUnknown;
        pusDomainName = &usEmpty;
        pusName = &usEmpty;

        //
        // Link domain, name and sid name use.
        //
        if (pNames) {

            domainIndex = pNames->DomainIndex;
            if (domainIndex < domainsEntries)
                pusDomainName = &referencedDomains->Domains[domainIndex].Name;

            pusName = &pNames->Name;
            sidNameUse = pNames->Use;
            pNames++;

        }

        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        pSidNameUseString = supGetSidNameUse(sidNameUse);

        //
        // Dump sid name use.
        //
        switch (sidNameUse) {
        case SidTypeInvalid:
        case SidTypeUnknown:

            RtlStringCchPrintfSecure(szBuffer,
                RTL_NUMBER_OF(szBuffer),
                TEXT("[%wZ] [%wS]"),
                &stringSid,
                pSidNameUseString);

            break;

        default:

            RtlStringCchPrintfSecure(szBuffer,
                RTL_NUMBER_OF(szBuffer),
                TEXT("[%wZ] '%wZ\\%wZ' [%wS]"),
                &stringSid,
                pusDomainName,
                pusName,
                pSidNameUseString);

            break;
        }

        RtlFreeUnicodeString(&stringSid);
        OutputCallback(Context, szBuffer, CallbackContext);

    }
    __finally {
        if (referencedDomains) LsaFreeMemory(referencedDomains);
        if (translatedNames) LsaFreeMemory(translatedNames);
    }
}

/*
* SDViewDumpObjectSecurity
*
* Purpose:
*
* Dump object security information (dacl, sacl, sid).
*
*/
NTSTATUS SDViewDumpObjectSecurity(
    _In_ SDVIEW_CONTEXT* Context
)
{
    NTSTATUS ntStatus, ntQueryStatus;
    ULONG daclCount = 0, saclCount = 0;
    HANDLE hObject = NULL;
    LSA_HANDLE hPolicy = NULL;
    LSA_OBJECT_ATTRIBUTES lsaOa;

    PACL pAcl;
    PSID pOwnerSid;
    PSECURITY_DESCRIPTOR pSD = NULL;

    BOOLEAN bDefaulted = FALSE, bPresent = FALSE;

    __try {

        ntStatus = supOpenNamedObjectByType(&hObject,
            Context->Type,
            Context->Directory,
            Context->Name,
            READ_CONTROL);

        if (!NT_SUCCESS(ntStatus))
            __leave;

        InitializeObjectAttributes((OBJECT_ATTRIBUTES*)&lsaOa, NULL, 0, 0, NULL);

        ntStatus = LsaOpenPolicy(NULL, &lsaOa, POLICY_LOOKUP_NAMES, &hPolicy);
        if (!NT_SUCCESS(ntStatus))
            __leave;

        ntStatus = supQuerySecurityInformation(
            hObject,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
            LABEL_SECURITY_INFORMATION | PROCESS_TRUST_LABEL_SECURITY_INFORMATION,
            &pSD,
            NULL);

        if (!NT_SUCCESS(ntStatus))
            __leave;

        pOwnerSid = NULL;
        ntQueryStatus = RtlGetOwnerSecurityDescriptor(pSD, &pOwnerSid, &bDefaulted);
        if (NT_SUCCESS(ntQueryStatus)) {

            SDViewDumpSid(Context, pOwnerSid, hPolicy,
                &OutputSidCallback, NULL);

        }

        pAcl = NULL;
        ntQueryStatus = RtlGetDaclSecurityDescriptor(pSD, &bPresent, &pAcl, &bDefaulted);
        if (NT_SUCCESS(ntQueryStatus)) {

            daclCount = SDViewDumpAcl(Context, pAcl, hPolicy,
                &OutputAclEntryCallback, IntToPtr(0));

        }

        pAcl = NULL;
        ntQueryStatus = RtlGetSaclSecurityDescriptor(pSD, &bPresent, &pAcl, &bDefaulted);
        if (NT_SUCCESS(ntQueryStatus)) {

            saclCount = SDViewDumpAcl(Context, pAcl, hPolicy,
                &OutputAclEntryCallback, IntToPtr(1));

        }

        SDViewUpdateStatusBar(Context, daclCount, saclCount);

    }
    __finally {
        if (pSD) supHeapFree(pSD);
        if (hPolicy) LsaClose(hPolicy);
        if (hObject) NtClose(hObject);
    }

    return ntStatus;
}

/*
* SDViewInitControls
*
* Purpose:
*
* Initialize controls.
*
*/
VOID SDViewInitControls(
    _In_ HWND hwndDlg,
    _In_ SDVIEW_CONTEXT* Context
)
{
    LVGROUP lvg;
    LVCOLUMNS_DATA columnData[] =
    {
        { L"AceType", 80, LVCFMT_CENTER, I_IMAGENONE },
        { L"AceFlags", 80, LVCFMT_CENTER, I_IMAGENONE },
        { L"AccessMask", 120, LVCFMT_CENTER, I_IMAGENONE },
        { L"SID", 120, LVCFMT_LEFT, I_IMAGENONE },
        { L"Domain\\Name", 200, LVCFMT_LEFT, I_IMAGENONE },
        { L"UseName", 120, LVCFMT_LEFT, I_IMAGENONE }
    };

    struct LVGroups {
        LPWSTR Name;
        INT Id;
    } groupData[] = {
        { L"ACL", 0 },
        { L"SACL", 1 }
    };

    INT i;
    HWND aclList = GetDlgItem(hwndDlg, IDC_SDVIEW_LIST);
    HWND sidOwner = GetDlgItem(hwndDlg, IDC_SDVIEW_OWNER);
    HWND okButton = GetDlgItem(hwndDlg, IDOK);

    //
    // Set listview style flags and theme.
    //
    supSetListViewSettings(aclList,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP,
        FALSE,
        TRUE,
        NULL,
        0);

    SendMessage(aclList, LVM_ENABLEGROUPVIEW, 1, 0);

    //
    // Add listview columns.
    //
    supAddLVColumnsFromArray(
        aclList,
        columnData,
        RTL_NUMBER_OF(columnData));

    RtlSecureZeroMemory(&lvg, sizeof(lvg));
    lvg.cbSize = sizeof(LVGROUP);
    lvg.mask = LVGF_HEADER | LVGF_ALIGN | LVGF_GROUPID;
    lvg.uAlign = LVGA_HEADER_LEFT;

    for (i = 0; i < RTL_NUMBER_OF(groupData); i++) {
        lvg.pszHeader = groupData[i].Name;
        lvg.cchHeader = (INT)_strlen(lvg.pszHeader);
        lvg.iGroupId = groupData[i].Id;
        SendMessage(aclList, LVM_INSERTGROUP, (WPARAM)i, (LPARAM)&lvg);
    }

    SetWindowText(sidOwner, T_EmptyString);

    GetClientRect(hwndDlg, &Context->WindowRect);
    GetWindowRect(aclList, &Context->ListRect);
    GetWindowRect(okButton, &Context->ButtonRect);
    ScreenToClient(hwndDlg, (LPPOINT)&Context->ButtonRect);
}

/*
* SdViewHandlePopup
*
* Purpose:
*
* List popup construction.
*
*/
VOID SDViewHandlePopup(
    _In_ HWND hwndDlg,
    _In_ LPPOINT lpPoint,
    _In_ PVOID lpUserParam
)
{
    HMENU hMenu;
    SDVIEW_CONTEXT* Context = (SDVIEW_CONTEXT*)lpUserParam;
    HWND hwndList = GetDlgItem(hwndDlg, IDC_SDVIEW_LIST);

    hMenu = CreatePopupMenu();
    if (hMenu) {

        if (supListViewAddCopyValueItem(hMenu,
            hwndList,
            ID_OBJECT_COPY,
            0,
            lpPoint,
            &Context->iSelectedItem,
            &Context->iColumnHit))
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
* SDViewOnResize
*
* Purpose:
*
* WM_SIZE handler.
*
*/
VOID SDViewOnResize(
    _In_ SDVIEW_CONTEXT* Context,
    _In_ HWND hwndDlg,
    _In_ LPARAM lParam
)
{
    HWND hwndList = GetDlgItem(hwndDlg, IDC_SDVIEW_LIST);
    HWND hwndButton = GetDlgItem(hwndDlg, IDOK);
    WORD dlgWidth = LOWORD(lParam), dlgHeight = HIWORD(lParam);

    INT dx, dy;

    dx = Context->WindowRect.right - Context->ListRect.right;
    dy = Context->WindowRect.bottom - Context->ListRect.bottom;

    SetWindowPos(hwndList, NULL, 0, 0,
        dlgWidth - dx - Context->ListRect.left,
        dlgHeight - dy - Context->ListRect.top,
        SWP_NOMOVE);

    dx = Context->WindowRect.right - Context->ButtonRect.left;
    dy = Context->WindowRect.bottom - Context->ButtonRect.top;

    SetWindowPos(hwndButton, NULL,
        dlgWidth - dx,
        dlgHeight - dy,
        0, 0,
        SWP_NOSIZE);

    SendMessage(Context->StatusBar, WM_SIZE, 0, 0);
    RedrawWindow(hwndDlg, NULL, 0, RDW_ERASE | RDW_INVALIDATE | RDW_ERASENOW);
}

/*
* SDViewDialogProc
*
* Purpose:
*
* View Security Descriptor Dialog Window Procedure
*
* During WM_INITDIALOG centers window and initializes security descriptor info
*
*/
INT_PTR CALLBACK SDViewDialogProc(
    _In_ HWND   hwndDlg,
    _In_ UINT   uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    SDVIEW_CONTEXT* dlgContext;

    switch (uMsg) {

    case WM_INITDIALOG:
        supCenterWindow(hwndDlg);
        if (lParam) {
            dlgContext = (SDVIEW_CONTEXT*)lParam;
            SetProp(hwndDlg, T_DLGCONTEXT, (HANDLE)lParam);
            SDViewInitControls(hwndDlg, dlgContext);
        }
        break;

    case WM_CONTEXTMENU:

        dlgContext = (SDVIEW_CONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (dlgContext) {

            supHandleContextMenuMsgForListView(hwndDlg,
                wParam,
                lParam,
                dlgContext->AceList,
                (pfnPopupMenuHandler)SDViewHandlePopup,
                (PVOID)dlgContext);

        }
        break;

    case WM_SIZE:
        dlgContext = (SDVIEW_CONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (dlgContext) {
            SDViewOnResize(dlgContext, hwndDlg, lParam);
        }
        break;

    case WM_CLOSE:
        dlgContext = (SDVIEW_CONTEXT*)RemoveProp(hwndDlg, T_DLGCONTEXT);
        if (dlgContext) {
            if (dlgContext->DialogIcon)
                DestroyIcon(dlgContext->DialogIcon);

            FreeSDViewContext(dlgContext);
        }
        return DestroyWindow(hwndDlg);

    case WM_GETMINMAXINFO:
        if (lParam) {
            supSetMinMaxTrackSize((PMINMAXINFO)lParam,
                SDVIEWDLG_TRACKSIZE_MIN_X,
                SDVIEWDLG_TRACKSIZE_MIN_Y,
                TRUE);
        }
        break;

    case WM_COMMAND:

        switch (GET_WM_COMMAND_ID(wParam, lParam)) {
        case IDCANCEL:
        case IDOK:
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            break;

        case ID_OBJECT_COPY:
            dlgContext = (SDVIEW_CONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
            if (dlgContext) {
                supListViewCopyItemValueToClipboard(dlgContext->AceList,
                    dlgContext->iSelectedItem,
                    dlgContext->iColumnHit);
            }
            break;
        default:
            break;

        }
    default:
        return FALSE;
    }

    return TRUE;
}

/*
* SDViewSetCaptionTextFormatted
*
* Purpose:
*
* Set dialog window caption text.
*
*/
VOID SDViewSetCaptionTextFormatted(
    _In_ HWND DialogWindow,
    _In_ LPWSTR ObjectDirectory,
    _In_opt_ LPWSTR ObjectName
)
{
    LPWSTR lpText;
    SIZE_T cch, l;

    cch = MAX_PATH + _strlen(ObjectDirectory);
    if (ObjectName) cch += _strlen(ObjectName);

    lpText = (LPWSTR)supHeapAlloc(cch * sizeof(WCHAR));
    if (lpText) {

        _strcpy(lpText, TEXT("Security Descriptor ("));
        _strcat(lpText, ObjectDirectory);
        l = _strlen(ObjectDirectory);
        if (ObjectDirectory[l - 1] != L'\\') {
            _strcat(lpText, TEXT("\\"));
        }
        if (ObjectName) {
            _strcat(lpText, ObjectName);
        }
        _strcat(lpText, TEXT(")"));
        SetWindowText(DialogWindow, lpText);
        supHeapFree(lpText);
    }
}

/*
* SDViewSetCaption
*
* Purpose:
*
* Format and set dialog window caption text as "Security Descriptor (ObjectDirectory\ObjectName)".
*
*/
VOID SDViewSetCaption(
    _In_ HWND DialogWindow,
    _In_ LPWSTR ObjectDirectory,
    _In_ LPWSTR ObjectName,
    _In_ WOBJ_OBJECT_TYPE ObjectType
)
{
    SIZE_T i, l, rdirLen, ldirSz;
    LPWSTR SingleDirName, ParentDir;


    if (ObjectType == ObjectTypeDirectory) {

        //
        // Root case.
        //
        if (_strcmpi(ObjectName, KM_OBJECTS_ROOT_DIRECTORY) == 0) {
            SDViewSetCaptionTextFormatted(DialogWindow, ObjectDirectory, NULL);
            return;
        }

    }

    //
    // Extract parent directory name, handle self case.
    //
    l = 0;
    rdirLen = _strlen(ObjectDirectory);
    for (i = 0; i < rdirLen; i++) {
        if (ObjectDirectory[i] == L'\\')
            l = i + 1;
    }

    SingleDirName = &ObjectDirectory[l];

    if (_strcmpi(SingleDirName, ObjectName) == 0) {

        ldirSz = rdirLen * sizeof(WCHAR) + sizeof(UNICODE_NULL);
        ParentDir = (LPWSTR)supHeapAlloc(ldirSz);
        if (ParentDir) {
            if (l == 1) l++;
            supCopyMemory(ParentDir, ldirSz, ObjectDirectory, (l - 1) * sizeof(WCHAR));
            SDViewSetCaptionTextFormatted(DialogWindow, ParentDir, ObjectName);
            supHeapFree(ParentDir);
        }

    }
    else {
        SDViewSetCaptionTextFormatted(DialogWindow, ObjectDirectory, ObjectName);
    }

}

/*
* SDViewDialogCreate
*
* Purpose:
*
* Create and initialize ViewSecurityDescriptor Dialog.
*
*/
VOID SDViewDialogCreate(
    _In_ HWND ParentWindow,
    _In_ LPWSTR ObjectDirectory,
    _In_ LPWSTR ObjectName,
    _In_ WOBJ_OBJECT_TYPE ObjectType
)
{
    HICON hIcon;
    HWND hwndDlg;
    NTSTATUS ntStatus;
    SDVIEW_CONTEXT* SDViewContext;
    LPWSTR lpText;

    ENUMCHILDWNDDATA wndData;

    if (ObjectDirectory == NULL || ObjectName == NULL)
        return;

    SDViewContext = AllocateSDViewContext(ObjectDirectory,
        ObjectName,
        ObjectType);

    if (SDViewContext == NULL)
        return;

    hwndDlg = CreateDialogParam(g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_SDVIEW),
        ParentWindow,
        (DLGPROC)&SDViewDialogProc,
        (LPARAM)SDViewContext);

    if (hwndDlg) {

        //
        // Set dialog icon.
        //
        hIcon = (HICON)LoadImage(g_WinObj.hInstance,
            MAKEINTRESOURCE(IDI_ICON_MAIN),
            IMAGE_ICON,
            32, 32,
            0);

        if (hIcon) {
            SendMessage(hwndDlg, WM_SETICON, (WPARAM)ICON_SMALL, (LPARAM)hIcon);
            SendMessage(hwndDlg, WM_SETICON, (WPARAM)ICON_BIG, (LPARAM)hIcon);
            SDViewContext->DialogIcon = hIcon;
        }

        SDViewContext->DialogWindow = hwndDlg;
        SDViewContext->AceList = GetDlgItem(hwndDlg, IDC_SDVIEW_LIST);
        SDViewContext->StatusBar = GetDlgItem(hwndDlg, IDC_SDVIEW_STATUSBAR);

        SDViewSetCaption(hwndDlg, ObjectDirectory, ObjectName, ObjectType);

        //
        // Dump object security information.
        //
        ntStatus = SDViewDumpObjectSecurity(SDViewContext);
        if (NT_SUCCESS(ntStatus)) {
            SetFocus(SDViewContext->AceList);
        }
        else {
            //
            // On error - hide all child windows and show details of the error.
            //
            if (GetWindowRect(hwndDlg, &wndData.Rect)) {
                wndData.nCmdShow = SW_HIDE;
                EnumChildWindows(hwndDlg, supCallbackShowChildWindow, (LPARAM)&wndData);
            }
            ShowWindow(GetDlgItem(hwndDlg, ID_OBJECTDUMPERROR), SW_SHOW);
            lpText = supFormatNtError(ntStatus);
            if (lpText) {
                SetDlgItemText(hwndDlg, ID_OBJECTDUMPERROR, lpText);
                LocalFree((HLOCAL)lpText);
            }
        }
    }
    else {
        supHeapFree(SDViewContext);
    }
}
