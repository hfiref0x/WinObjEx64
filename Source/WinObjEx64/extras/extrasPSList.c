/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       EXTRASPSLIST.C
*
*  VERSION:     1.71
*
*  DATE:        31 Jan 2019
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "extras.h"
#include "extrasPSList.h"
#include "treelist\treelist.h"

ATOM g_PsTreeListAtom;

EXTRASCONTEXT PsDlgContext;

/*
* PsListDialogResize
*
* Purpose:
*
* WM_SIZE handler.
*
*/
INT_PTR PsListDialogResize(
    VOID
)
{
    RECT r1;
    INT  cy;

    RtlSecureZeroMemory(&r1, sizeof(r1));

    GetClientRect(PsDlgContext.hwndDlg, &r1);

    cy = r1.bottom - 24;
    if (PsDlgContext.SizeGrip != 0)
        cy -= GRIPPER_SIZE;

    SetWindowPos(PsDlgContext.TreeList, 0, 0, 0,
        r1.right - 24,
        cy,
        SWP_NOMOVE | SWP_NOZORDER);

    if (PsDlgContext.SizeGrip != 0)
        supSzGripWindowOnResize(PsDlgContext.hwndDlg, PsDlgContext.SizeGrip);

    return 1;
}

/*
* PsListHandlePopupMenu
*
* Purpose:
*
* Process list popup construction
*
*/
VOID PsListHandlePopupMenu(
    _In_ HWND hwndDlg
)
{
    POINT pt1;
    HMENU hMenu;

    if (GetCursorPos(&pt1) == FALSE)
        return;

    hMenu = CreatePopupMenu();
    if (hMenu) {
        InsertMenu(hMenu, 0, MF_BYCOMMAND, ID_OBJECT_COPY, T_COPYEPROCESS);
        TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, pt1.x, pt1.y, 0, hwndDlg, NULL);
        DestroyMenu(hMenu);
    }
}

/*
* PsListDialogProc
*
* Purpose:
*
* Drivers Dialog window procedure.
*
*/
INT_PTR CALLBACK PsListDialogProc(
    _In_  HWND hwndDlg,
    _In_  UINT uMsg,
    _In_  WPARAM wParam,
    _In_  LPARAM lParam
)
{
    UNREFERENCED_PARAMETER(wParam);

    switch (uMsg) {

    case WM_CONTEXTMENU:
        PsListHandlePopupMenu(hwndDlg);
        break;

    case WM_COMMAND:

        switch (LOWORD(wParam)) {
        case IDCANCEL:
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            return TRUE;
        case ID_OBJECT_COPY:
            supCopyTreeListSubItemValue(PsDlgContext.TreeList, 0);
            break;
        default:
            break;
        }
        break;

    case WM_INITDIALOG:
        supCenterWindow(hwndDlg);
        break;

    case WM_GETMINMAXINFO:
        if (lParam) {
            ((PMINMAXINFO)lParam)->ptMinTrackSize.x = 640;
            ((PMINMAXINFO)lParam)->ptMinTrackSize.y = 480;
        }
        break;

    case WM_SIZE:
        return PsListDialogResize();

    case WM_CLOSE:
        DestroyWindow(PsDlgContext.TreeList);
        UnregisterClass(MAKEINTATOM(g_PsTreeListAtom), g_WinObj.hInstance);

        if (PsDlgContext.SizeGrip) DestroyWindow(PsDlgContext.SizeGrip);
        DestroyWindow(hwndDlg);
        g_WinObj.AuxDialogs[wobjPsListDlgId] = NULL;
        return TRUE;
    }

    return FALSE;
}

/*
* PsListProcessInServicesList
*
* Purpose:
*
* Return TRUE if given process is in SCM snapshot.
*
*/
BOOLEAN PsListProcessInServicesList(
    _In_ HANDLE ProcessId,
    _In_ SCMDB *ServicesList
)
{
    DWORD u;
    LPENUM_SERVICE_STATUS_PROCESS pInfo = NULL;

    pInfo = (LPENUM_SERVICE_STATUS_PROCESS)ServicesList->Entries;
    for (u = 0; u < ServicesList->NumberOfEntries; u++) {
        if (pInfo[u].ServiceStatusProcess.dwProcessId)
            if (UlongToHandle(pInfo[u].ServiceStatusProcess.dwProcessId) == ProcessId)
            {
                return TRUE;
            }
    }
    return FALSE;
}

#define T_IDLE_PROCESS TEXT("Idle")
#define T_IDLE_PROCESS_LENGTH sizeof(T_IDLE_PROCESS)

/*
* AddProcessEntryTreeList
*
* Purpose:
*
* Insert process entry to the treelist.
*
*/
HTREEITEM AddProcessEntryTreeList(
    _In_opt_ HTREEITEM RootItem,
    _In_ OBEX_PROCESS_LOOKUP_ENTRY* Entry,
    _In_ PSYSTEM_HANDLE_INFORMATION_EX HandleList,
    _In_ SCMDB *ServicesList,
    _In_ PSID OurSid
)
{
    HTREEITEM hTreeItem = NULL;
    PSID ProcessSid;
    PSYSTEM_PROCESSES_INFORMATION processEntry;
    TL_SUBITEMS_FIXED subitems;

    ULONG_PTR ObjectAddress = 0;

    DWORD CurrentProcessId = GetCurrentProcessId();

    NTSTATUS status;
    ULONG Length, r, fState = 0;
    PWSTR Caption, P, UserName = NULL;

    LSA_OBJECT_ATTRIBUTES lobja;
    LSA_HANDLE PolicyHandle = NULL;
    PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains = NULL;
    PLSA_TRANSLATED_NAME Names = NULL;
    SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;

    PROCESS_EXTENDED_BASIC_INFORMATION exbi;
    WCHAR szEPROCESS[32];

    SID SidLocalService = { SID_REVISION, 1, SECURITY_NT_AUTHORITY, { SECURITY_LOCAL_SERVICE_RID } };

    RtlSecureZeroMemory(&subitems, sizeof(subitems));

    //
    // Id + Name
    //
    processEntry = Entry->ProcessInformation;

    Length = 32;
    if (processEntry->ImageName.Length) {
        Length += processEntry->ImageName.Length;
    }
    else {
        if (processEntry->UniqueProcessId == 0) {
            Length += T_IDLE_PROCESS_LENGTH;
        }
    }

    Caption = (PWSTR)supHeapAlloc(Length);

    P = _strcat(Caption, TEXT("["));
    ultostr((ULONG)processEntry->UniqueProcessId, P);
    _strcat(Caption, TEXT("]"));

    _strcat(Caption, TEXT(" "));

    if (processEntry->UniqueProcessId == 0) {
        _strcat(Caption, T_IDLE_PROCESS);
    }
    else {
        _strcat(Caption, processEntry->ImageName.Buffer);
    }

    //
    // EPROCESS value
    //
    szEPROCESS[0] = 0;

    for (r = 0; r < HandleList->NumberOfHandles; r++)
        if (HandleList->Handles[r].UniqueProcessId == (ULONG_PTR)CurrentProcessId) {
            if (HandleList->Handles[r].HandleValue == (ULONG_PTR)Entry->hProcess) {
                ObjectAddress = (ULONG_PTR)HandleList->Handles[r].Object;
                break;
            }
        }

    if (ObjectAddress) {
        szEPROCESS[0] = L'0';
        szEPROCESS[1] = L'x';
        u64tohex(ObjectAddress, &szEPROCESS[2]);
    }

    subitems.UserParam = processEntry->UniqueProcessId;
    subitems.Count = 2;
    subitems.Text[0] = szEPROCESS;

    //
    // Colors.
    //
    //
    // 1. Services.
    //

    ProcessSid = supQueryProcessSid(Entry->hProcess);


    if (PsListProcessInServicesList(processEntry->UniqueProcessId, ServicesList) ||
        ((ProcessSid) && RtlEqualSid(&SidLocalService, ProcessSid)))
    {
        subitems.ColorFlags = TLF_BGCOLOR_SET;
        subitems.BgColor = 0xd0d0ff;
        fState = TVIF_STATE;
    }

    //
    // 2. Current user processes.
    //
    if (ProcessSid) {
        if (RtlEqualSid(OurSid, ProcessSid)) {
            subitems.ColorFlags = TLF_BGCOLOR_SET;
            subitems.BgColor = 0xffd0d0;
            fState = TVIF_STATE;
        }
    }

    //
    // 3. Store processes.
    //
    if (g_ExtApiSet.IsImmersiveProcess) {
        if (g_ExtApiSet.IsImmersiveProcess(Entry->hProcess)) {
            subitems.ColorFlags = TLF_BGCOLOR_SET;
            subitems.BgColor = 0xeaea00;
            fState = TVIF_STATE;
        }
    }

    //
    // 4. Protected processes.
    //
    exbi.Size = sizeof(PROCESS_EXTENDED_BASIC_INFORMATION);
    if (NT_SUCCESS(NtQueryInformationProcess(Entry->hProcess, ProcessBasicInformation,
        &exbi, sizeof(exbi), &r)))
    {
        if (exbi.IsProtectedProcess) {
            subitems.ColorFlags = TLF_BGCOLOR_SET;
            subitems.BgColor = 0xe6ffe6;
            fState = TVIF_STATE;
        }
    }

    //
    // User.
    //
    if (ProcessSid) {

        SecurityQualityOfService.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
        SecurityQualityOfService.ImpersonationLevel = SecurityImpersonation;
        SecurityQualityOfService.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
        SecurityQualityOfService.EffectiveOnly = FALSE;

        InitializeObjectAttributes(
            &lobja,
            NULL,
            0L,
            NULL,
            NULL);

        lobja.SecurityQualityOfService = &SecurityQualityOfService;

        if (NT_SUCCESS(LsaOpenPolicy(NULL,
            (PLSA_OBJECT_ATTRIBUTES)&lobja,
            POLICY_LOOKUP_NAMES,
            (PLSA_HANDLE)&PolicyHandle)))
        {
            status = LsaLookupSids(
                PolicyHandle,
                1,
                (PSID*)&ProcessSid,
                (PLSA_REFERENCED_DOMAIN_LIST*)&ReferencedDomains,
                (PLSA_TRANSLATED_NAME*)&Names);

            if ((NT_SUCCESS(status)) && (status != STATUS_SOME_NOT_MAPPED)) {

                Length = 0;

                if ((ReferencedDomains != NULL) && (Names != NULL)) {

                    Length = 4 + ReferencedDomains->Domains[0].Name.MaximumLength +
                        Names->Name.MaximumLength;

                    UserName = (LPWSTR)supHeapAlloc(r);
                    if (UserName) {

                        _strncpy(UserName, 
                            Length,
                            ReferencedDomains->Domains[0].Name.Buffer,
                            ReferencedDomains->Domains[0].Name.Length);
                        
                        Length -= ReferencedDomains->Domains[0].Name.Length;

                        P = _strcat(UserName, TEXT("\\"));

                        Length -= sizeof(WCHAR);

                        _strncpy(P,
                            Length,
                            Names->Name.Buffer,
                            Names->Name.Length);
                         
                        subitems.Text[1] = UserName;
                    }
                }
                if (ReferencedDomains) LsaFreeMemory(ReferencedDomains);
                if (Names) LsaFreeMemory(Names);
            }
            LsaClose(PolicyHandle);
        }
        supHeapFree(ProcessSid);
    }

    hTreeItem = TreeListAddItem(
        PsDlgContext.TreeList,
        RootItem,
        TVIF_TEXT | fState,
        0,
        0,
        Caption,
        &subitems);

    if (UserName)
        supHeapFree(UserName);

    return hTreeItem;
}

typedef BOOL(CALLBACK *FINDITEMCALLBACK)(
    HWND TreeList,
    HTREEITEM htItem,
    ULONG_PTR UserContext
    );

/*
* FindItemByProcessIdCallback
*
* Purpose:
*
* Search callback.
*
*/
BOOL CALLBACK FindItemMatchCallback(
    _In_ HWND TreeList,
    _In_ HTREEITEM htItem,
    _In_ ULONG_PTR UserContext
)
{
    HANDLE             ParentProcessId = (HANDLE)UserContext;
    TL_SUBITEMS_FIXED *subitems = NULL;
    TVITEMEX           itemex;

    RtlSecureZeroMemory(&itemex, sizeof(itemex));
    itemex.hItem = htItem;
    TreeList_GetTreeItem(TreeList, &itemex, &subitems);

    if (subitems) {
        if (subitems->UserParam == NULL)
            return FALSE;

        return (ParentProcessId == subitems->UserParam);
    }

    return FALSE;
}

/*
* FindItemRecursive
*
* Purpose:
*
* Recursive find item.
*
*/
HTREEITEM FindItemRecursive(
    _In_ HWND TreeList,
    _In_ HTREEITEM htStart,
    _In_ FINDITEMCALLBACK FindItemCallback,
    _In_ ULONG_PTR UserContext
)
{
    HTREEITEM htItemMatch = NULL;
    HTREEITEM htItemCurrent = htStart;

    if (FindItemCallback == NULL)
        return NULL;

    while (htItemCurrent != NULL && htItemMatch == NULL) {
        if (FindItemCallback(TreeList, htItemCurrent, UserContext)) {
            htItemMatch = htItemCurrent;
        }
        else {
            htItemMatch = FindItemRecursive(TreeList,
                TreeList_GetChild(TreeList, htItemCurrent), FindItemCallback, UserContext);
        }
        htItemCurrent = TreeList_GetNextSibling(TreeList, htItemCurrent);
    }
    return htItemMatch;
}

/*
* FindParentItem
*
* Purpose:
*
* Return treelist item with given parent process id.
*
*/
HTREEITEM FindParentItem(
    _In_ HWND TreeList,
    _In_ HANDLE ParentProcessId
)
{
    HTREEITEM htiRoot = TreeList_GetRoot(TreeList);
    return FindItemRecursive(TreeList,
        htiRoot, FindItemMatchCallback, (ULONG_PTR)ParentProcessId);
}

//
// These constants missing in Windows SDK 8.1
//
#ifndef SERVICE_USER_SERVICE
#define SERVICE_USER_SERVICE           0x00000040
#endif

#ifndef SERVICE_USERSERVICE_INSTANCE
#define SERVICE_USERSERVICE_INSTANCE   0x00000080
#endif

/*
* CreateProcessTreeList
*
* Purpose:
*
* Build and output process tree list.
*
*/
VOID CreateProcessTreeList()
{
    DWORD ServiceEnumType;
    ULONG NextEntryDelta = 0, NumberOfProcesses = 0;

    HTREEITEM ViewRootHandle;

    HANDLE hProcess = NULL;
    PVOID InfoBuffer = NULL;
    PSYSTEM_HANDLE_INFORMATION_EX pHandles = NULL;
    PSID OurSid = NULL;

    OBEX_PROCESS_LOOKUP_ENTRY *spl = NULL, *LookupEntry;

    SCMDB ServicesList;

    OBJECT_ATTRIBUTES obja = RTL_INIT_OBJECT_ATTRIBUTES((PUNICODE_STRING)NULL, 0);

    union {
        PSYSTEM_PROCESSES_INFORMATION Processes;
        PBYTE ListRef;
    } List;

    __try {
        ServicesList.NumberOfEntries = 0;
        ServicesList.Entries = NULL;

        OurSid = supQueryProcessSid(NtCurrentProcess());

        if (g_NtBuildNumber >= 14393) {
            ServiceEnumType = SERVICE_TYPE_ALL;
        }
        else if (g_NtBuildNumber >= 10240) {
            ServiceEnumType = SERVICE_WIN32 |
                SERVICE_ADAPTER |
                SERVICE_DRIVER |
                SERVICE_INTERACTIVE_PROCESS |
                SERVICE_USER_SERVICE |
                SERVICE_USERSERVICE_INSTANCE;
        }
        else {
            ServiceEnumType = SERVICE_DRIVER | SERVICE_WIN32;
        }
        if (!supCreateSCMSnapshot(ServiceEnumType, &ServicesList))
            __leave;

        InfoBuffer = supGetSystemInfo(SystemProcessInformation);
        if (InfoBuffer == NULL)
            __leave;

        List.ListRef = (PBYTE)InfoBuffer;

        //
        // Calculate process handle list size.
        //
        do {

            List.ListRef += NextEntryDelta;

            if (List.Processes->ThreadCount)
                NumberOfProcesses += 1;

            NextEntryDelta = List.Processes->NextEntryDelta;

        } while (NextEntryDelta);

        //
        // Build process handle list.
        //
        spl = (OBEX_PROCESS_LOOKUP_ENTRY*)supHeapAlloc(NumberOfProcesses * sizeof(OBEX_PROCESS_LOOKUP_ENTRY));
        if (spl == NULL)
            __leave;

        LookupEntry = spl;

        NextEntryDelta = 0;
        List.ListRef = (PBYTE)InfoBuffer;

        do {
            List.ListRef += NextEntryDelta;
            hProcess = NULL;

            if (List.Processes->ThreadCount) {
                NtOpenProcess(
                    &hProcess,
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    &obja,
                    &List.Processes->Threads[0].ClientId);
            }

            LookupEntry->hProcess = hProcess;
            LookupEntry->EntryPtr = List.ListRef;
            LookupEntry = (OBEX_PROCESS_LOOKUP_ENTRY*)RtlOffsetToPointer(LookupEntry,
                sizeof(OBEX_PROCESS_LOOKUP_ENTRY));

            NextEntryDelta = List.Processes->NextEntryDelta;

        } while (NextEntryDelta);

        pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation);
        if (pHandles == NULL)
            __leave;

        //
        // Output all process entries.
        //
        LookupEntry = spl;

        //idle
        AddProcessEntryTreeList(NULL,
            LookupEntry, pHandles, &ServicesList, OurSid);

        NumberOfProcesses--;
        ViewRootHandle = NULL;

        while (NumberOfProcesses) {

            LookupEntry = (OBEX_PROCESS_LOOKUP_ENTRY*)RtlOffsetToPointer(
                LookupEntry, sizeof(OBEX_PROCESS_LOOKUP_ENTRY));

            ViewRootHandle = FindParentItem(PsDlgContext.TreeList,
                LookupEntry->ProcessInformation->InheritedFromUniqueProcessId);

            if (ViewRootHandle == NULL) {
                ViewRootHandle = AddProcessEntryTreeList(NULL,
                    LookupEntry, pHandles, &ServicesList, OurSid);
            }
            else {
                AddProcessEntryTreeList(ViewRootHandle,
                    LookupEntry, pHandles, &ServicesList, OurSid);
            }

            if (LookupEntry->hProcess)
                NtClose(LookupEntry->hProcess);

            NumberOfProcesses--;
        }

    }
    __finally {
        if (OurSid) supHeapFree(OurSid);
        supFreeSCMSnapshot(&ServicesList);
        if (InfoBuffer) supHeapFree(InfoBuffer);
        if (pHandles) supHeapFree(pHandles);
        if (spl) supHeapFree(spl);
    }
}

/*
* extrasCreatePsListDialog
*
* Purpose:
*
* Create and initialize Process List Dialog.
*
*/
VOID extrasCreatePsListDialog(
    _In_ HWND hwndParent
)
{
    HDITEM   hdritem;
    RECT     rc;

    //allow only one dialog
    if (g_WinObj.AuxDialogs[wobjPsListDlgId]) {
        if (IsIconic(g_WinObj.AuxDialogs[wobjPsListDlgId]))
            ShowWindow(g_WinObj.AuxDialogs[wobjPsListDlgId], SW_RESTORE);
        else
            SetActiveWindow(g_WinObj.AuxDialogs[wobjPsListDlgId]);
        return;
    }

    RtlSecureZeroMemory(&PsDlgContext, sizeof(PsDlgContext));
    PsDlgContext.hwndDlg = CreateDialogParam(g_WinObj.hInstance, 
        MAKEINTRESOURCE(IDD_DIALOG_TREELIST_PLACEHOLDER),
        hwndParent, &PsListDialogProc, 0);

    if (PsDlgContext.hwndDlg == NULL) {
        return;
    }

    g_WinObj.AuxDialogs[wobjPsListDlgId] = PsDlgContext.hwndDlg;

    PsDlgContext.SizeGrip = supCreateSzGripWindow(PsDlgContext.hwndDlg);

    extrasSetDlgIcon(PsDlgContext.hwndDlg);
    SetWindowText(PsDlgContext.hwndDlg, TEXT("Processes"));

    GetClientRect(hwndParent, &rc);
    g_PsTreeListAtom = InitializeTreeListControl();
    PsDlgContext.TreeList = CreateWindowEx(WS_EX_CLIENTEDGE, WC_TREELIST, NULL,
        WS_VISIBLE | WS_CHILD | WS_TABSTOP | TLSTYLE_COLAUTOEXPAND, 12, 14,
        rc.right - 24, rc.bottom - 24, PsDlgContext.hwndDlg, NULL, NULL, NULL);

    if (PsDlgContext.TreeList) {
        RtlSecureZeroMemory(&hdritem, sizeof(hdritem));
        hdritem.mask = HDI_FORMAT | HDI_TEXT | HDI_WIDTH;
        hdritem.fmt = HDF_LEFT | HDF_BITMAP_ON_RIGHT | HDF_STRING;
        hdritem.cxy = 300;
        hdritem.pszText = TEXT("Process");
        TreeList_InsertHeaderItem(PsDlgContext.TreeList, 0, &hdritem);

        hdritem.cxy = 130;
        hdritem.pszText = TEXT("Object");
        TreeList_InsertHeaderItem(PsDlgContext.TreeList, 1, &hdritem);

        hdritem.cxy = 180;
        hdritem.pszText = TEXT("User");
        TreeList_InsertHeaderItem(PsDlgContext.TreeList, 2, &hdritem);
    }

    CreateProcessTreeList();

    PsListDialogResize();
}
