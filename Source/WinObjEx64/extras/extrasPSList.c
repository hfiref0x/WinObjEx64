/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2021
*
*  TITLE:       EXTRASPSLIST.C
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
#define OEMRESOURCE
#include "global.h"
#include "propDlg.h"
#include "extras.h"
#include "extrasPSList.h"
#include "treelist/treelist.h"
#include "resource.h"

#define Y_SPLITTER_SIZE 4
#define Y_SPLITTER_MIN  200

#define PSLISTDLG_TRACKSIZE_MIN_X 640
#define PSLISTDLG_TRACKSIZE_MIN_Y 480

#define T_IDLE_PROCESS TEXT("Idle")
#define T_IDLE_PROCESS_LENGTH sizeof(T_IDLE_PROCESS)

EXTRASCONTEXT   PsDlgContext;
static int      y_splitter_pos = 300, y_capture_pos = 0, y_splitter_max = 0;

HANDLE g_PsListWait = NULL;
ULONG g_DialogQuit = 0, g_DialogRefresh = 0;
HANDLE g_PsListHeap = NULL;

LIST_ENTRY g_PsListHead;

#define COLUMN_THREADLIST_TID              0
#define COLUMN_THREADLIST_PRIORITY         1
#define COLUMN_THREADLIST_STATE            2
#define COLUMN_THREADLIST_ETHREAD          3
#define COLUMN_THREADLIST_STARTADDRESS     4
#define COLUMN_THREADLIST_MODULE           5


/*
* PsxAllocateUnnamedObjectEntry
*
* Purpose:
*
* Allocate PROP_UNNAMED_OBJECT_INFO entry.
*
*/
PROP_UNNAMED_OBJECT_INFO* PsxAllocateUnnamedObjectEntry(
    _In_ PVOID Data,
    _In_ WOBJ_OBJECT_TYPE ObjectType
)
{
    PSYSTEM_PROCESSES_INFORMATION processEntry;
    PSYSTEM_THREAD_INFORMATION threadEntry;
    PROP_UNNAMED_OBJECT_INFO* objectEntry;

    if (Data == NULL)
        return NULL;

    objectEntry = (PROP_UNNAMED_OBJECT_INFO*)RtlAllocateHeap(g_PsListHeap,
        HEAP_ZERO_MEMORY, sizeof(PROP_UNNAMED_OBJECT_INFO));

    if (objectEntry == NULL)
        return NULL;

    if (ObjectType == ObjectTypeProcess) {

        processEntry = (PSYSTEM_PROCESSES_INFORMATION)Data;
        objectEntry->ClientId.UniqueProcess = processEntry->UniqueProcessId;
        objectEntry->ClientId.UniqueThread = NULL;

        objectEntry->ImageName.MaximumLength = processEntry->ImageName.MaximumLength;
        objectEntry->ImageName.Buffer = (PWSTR)RtlAllocateHeap(g_PsListHeap,
            HEAP_ZERO_MEMORY,
            objectEntry->ImageName.MaximumLength);
        if (objectEntry->ImageName.Buffer) {
            RtlCopyUnicodeString(&objectEntry->ImageName, &processEntry->ImageName);
        }
    }
    else if (ObjectType == ObjectTypeThread)
    {
        threadEntry = (PSYSTEM_THREAD_INFORMATION)Data;

        objectEntry->ClientId.UniqueProcess = threadEntry->ClientId.UniqueProcess;
        objectEntry->ClientId.UniqueThread = threadEntry->ClientId.UniqueThread;

        RtlCopyMemory(&objectEntry->ThreadInformation, Data, sizeof(SYSTEM_THREAD_INFORMATION));
    }
    return objectEntry;
}

/*
* PsxSCMLookupCallback
*
* Purpose:
*
* qsort, bsearch callback.
*
*/
int __cdecl PsxSCMLookupCallback(
    void const* first,
    void const* second
)
{
    int i;
    ENUM_SERVICE_STATUS_PROCESS* elem1 = (ENUM_SERVICE_STATUS_PROCESS*)first;
    ENUM_SERVICE_STATUS_PROCESS* elem2 = (ENUM_SERVICE_STATUS_PROCESS*)second;

    if (elem1->ServiceStatusProcess.dwProcessId == elem2->ServiceStatusProcess.dwProcessId)
        i = 0;
    else
        if (elem1->ServiceStatusProcess.dwProcessId < elem2->ServiceStatusProcess.dwProcessId)
            i = -1;
        else
            i = 1;

    return i;
}

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
    RECT r, szr;

    RtlSecureZeroMemory(&r, sizeof(RECT));
    RtlSecureZeroMemory(&szr, sizeof(RECT));

    SendMessage(PsDlgContext.StatusBar, WM_SIZE, 0, 0);
    GetClientRect(PsDlgContext.hwndDlg, &r);
    GetClientRect(PsDlgContext.StatusBar, &szr);
    y_splitter_max = r.bottom - Y_SPLITTER_MIN;

    SetWindowPos(PsDlgContext.TreeList, 0,
        0, 0,
        r.right,
        y_splitter_pos,
        SWP_NOOWNERZORDER);

    SetWindowPos(PsDlgContext.ListView, 0,
        0, y_splitter_pos + Y_SPLITTER_SIZE,
        r.right,
        r.bottom - y_splitter_pos - Y_SPLITTER_SIZE - szr.bottom,
        SWP_NOOWNERZORDER);

    return 1;
}

/*
* PsListHandlePopupMenu
*
* Purpose:
*
* Processes/threads list popup construction
*
*/
VOID PsListHandlePopupMenu(
    _In_ HWND hwndDlg,
    _In_ LPPOINT point,
    _In_ UINT itemCopy,
    _In_ UINT itemRefresh,
    _In_ BOOL fTreeList
)
{
    HMENU hMenu;
    UINT uPos = 0;

    hMenu = CreatePopupMenu();
    if (hMenu) {

        if (fTreeList) {
            InsertMenu(hMenu, uPos++, MF_BYCOMMAND, itemCopy, T_COPYOBJECT);
            InsertMenu(hMenu, uPos++, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
        }
        else {

            if (supListViewAddCopyValueItem(hMenu,
                PsDlgContext.ListView,
                itemCopy,
                uPos,
                point,
                &PsDlgContext.lvItemHit,
                &PsDlgContext.lvColumnHit))
            {
                InsertMenu(hMenu, ++uPos, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
            }

        }

        InsertMenu(hMenu, uPos, MF_BYCOMMAND, itemRefresh, T_VIEW_REFRESH);
        TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, point->x, point->y, 0, hwndDlg, NULL);
        DestroyMenu(hMenu);
    }

}

/*
* PsListCompareFunc
*
* Purpose:
*
* Dialog listview comparer function.
*
*/
INT CALLBACK PsListCompareFunc(
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort
)
{
    switch (lParamSort) {
    case COLUMN_THREADLIST_TID: //TID
    case COLUMN_THREADLIST_PRIORITY: //BasePriority
        return supGetMaxOfTwoULongFromString(
            PsDlgContext.ListView,
            lParam1,
            lParam2,
            PsDlgContext.lvColumnToSort,
            PsDlgContext.bInverseSort);
    case COLUMN_THREADLIST_STATE: //string (fixed size)
    case COLUMN_THREADLIST_MODULE: //string (fixed size)
        return supGetMaxCompareTwoFixedStrings(
            PsDlgContext.ListView,
            lParam1,
            lParam2,
            PsDlgContext.lvColumnToSort,
            PsDlgContext.bInverseSort);
    case COLUMN_THREADLIST_ETHREAD: //ethread (hex)
    case COLUMN_THREADLIST_STARTADDRESS: //address (hex)
        return supGetMaxOfTwoU64FromHex(
            PsDlgContext.ListView,
            lParam1,
            lParam2,
            PsDlgContext.lvColumnToSort,
            PsDlgContext.bInverseSort);
    }

    return 0;
}

/*
* PsListGetObjectEntry
*
* Purpose:
*
* Return pointer to data from selected object list entry.
*
*/
PROP_UNNAMED_OBJECT_INFO* PsListGetObjectEntry(
    _In_ BOOL bTreeList,
    _In_opt_ HTREEITEM hTreeItem)
{
    INT nSelected;
    TVITEMEX itemex;
    TL_SUBITEMS_FIXED* subitems = NULL;
    PROP_UNNAMED_OBJECT_INFO* ObjectEntry = NULL;

    if (bTreeList) {

        RtlSecureZeroMemory(&itemex, sizeof(itemex));

        if (hTreeItem) {
            itemex.hItem = hTreeItem;
        }
        else {
            itemex.hItem = TreeList_GetSelection(PsDlgContext.TreeList);
        }
        if (TreeList_GetTreeItem(PsDlgContext.TreeList, &itemex, &subitems))
            if (subitems)
                ObjectEntry = (PROP_UNNAMED_OBJECT_INFO*)subitems->UserParam;
    }
    else {
        nSelected = ListView_GetSelectionMark(PsDlgContext.ListView);
        supGetListViewItemParam(PsDlgContext.ListView, nSelected, (PVOID*)&ObjectEntry);
    }

    return ObjectEntry;
}

/*
* PsListHandleObjectProp
*
* Purpose:
*
* Show properties for selected object.
*
*/
VOID PsListHandleObjectProp(
    _In_ BOOL bProcessList,
    _In_ PROP_UNNAMED_OBJECT_INFO* ObjectEntry)
{
    SIZE_T sz;
    LPWSTR lpName;
    HANDLE UniqueProcessId = NULL, ObjectHandle = NULL;

    PUNICODE_STRING ImageName = NULL;

    PROP_UNNAMED_OBJECT_INFO* tempEntry;
    PROP_DIALOG_CREATE_SETTINGS propSettings;

    //
    // Only one process/thread properties dialog at the same time allowed.
    //
    ENSURE_DIALOG_UNIQUE(g_PsPropWindow);

    if (bProcessList) {

        UniqueProcessId = ObjectEntry->ClientId.UniqueProcess;
        if (NT_SUCCESS(supOpenProcess(
            UniqueProcessId,
            PROCESS_QUERY_LIMITED_INFORMATION,
            &ObjectHandle)))
        {
            supQueryObjectFromHandle(ObjectHandle, &ObjectEntry->ObjectAddress, NULL);
            NtClose(ObjectHandle);
        }

        ImageName = &ObjectEntry->ImageName;
    }
    else {

        tempEntry = PsListGetObjectEntry(TRUE, NULL);
        if (tempEntry) {
            UniqueProcessId = tempEntry->ClientId.UniqueProcess;
            ImageName = &tempEntry->ImageName;

            if (NT_SUCCESS(supOpenThread(
                &ObjectEntry->ClientId,
                THREAD_QUERY_LIMITED_INFORMATION,
                &ObjectHandle)))
            {
                supQueryObjectFromHandle(ObjectHandle, &ObjectEntry->ObjectAddress, NULL);
                NtClose(ObjectHandle);
            }

        }
    }

    if (ImageName == NULL)
        return;

    //
    // Create fake name for display.
    //
    sz = 1024 + (SIZE_T)ImageName->Length;
    lpName = (LPWSTR)supHeapAlloc(sz);
    if (lpName == NULL)
        return;

    if (ImageName->Length == 0) {
        if (UniqueProcessId == NULL) {
            _strcpy(lpName, T_IDLE_PROCESS);
        }
        else {
            _strcpy(lpName, TEXT("UnknownProcess"));
        }
    }
    else {
        RtlCopyMemory(lpName,
            ImageName->Buffer,
            ImageName->Length);
    }
    _strcat(lpName, TEXT(" PID:"));
    ultostr(HandleToULong(UniqueProcessId), _strend(lpName));

    if (!bProcessList) {
        _strcat(lpName, TEXT(" TID:"));
        ultostr(HandleToULong(ObjectEntry->ClientId.UniqueThread), _strend(lpName));
    }

    RtlSecureZeroMemory(&propSettings, sizeof(propSettings));

    propSettings.lpObjectName = lpName;
    propSettings.lpObjectType = (bProcessList) ? OBTYPE_NAME_PROCESS : OBTYPE_NAME_THREAD;
    propSettings.UnnamedObject = ObjectEntry;

    propCreateDialog(&propSettings);

    supHeapFree(lpName);
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
    _In_ SCMDB* ServicesList
)
{
    ENUM_SERVICE_STATUS_PROCESS* SearchEntrySCM = NULL, EntrySCM;

    if (ProcessId == NULL) return FALSE;

    EntrySCM.ServiceStatusProcess.dwProcessId = HandleToUlong(ProcessId);

    SearchEntrySCM = (ENUM_SERVICE_STATUS_PROCESS*)supBSearch(&EntrySCM,
        ServicesList->Entries,
        ServicesList->NumberOfEntries,
        sizeof(ENUM_SERVICE_STATUS_PROCESS),
        PsxSCMLookupCallback);

    return (SearchEntrySCM != NULL);
}

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
    _In_opt_ HANDLE ProcessHandle,
    _In_ PVOID Data,
    _In_ ULONG_PTR ObjectAddress,
    _In_opt_ SCMDB* ServicesList,
    _In_opt_ PSID OurSid,
    _In_opt_ LSA_HANDLE PolicyHandle
)
{
    HTREEITEM hTreeItem = NULL;
    PSID ProcessSid = NULL;
    HANDLE UniqueProcessId;
    PROP_UNNAMED_OBJECT_INFO* objectEntry;
    TL_SUBITEMS_FIXED subitems;

    ULONG Length, r;
    PWSTR Caption = NULL, PtrString, UserName = NULL;

    PROCESS_EXTENDED_BASIC_INFORMATION exbi;
    WCHAR szEPROCESS[32];

    SID SidLocalService = { SID_REVISION, 1, SECURITY_NT_AUTHORITY, { SECURITY_LOCAL_SERVICE_RID } };

    objectEntry = PsxAllocateUnnamedObjectEntry(Data, ObjectTypeProcess);
    if (objectEntry == NULL)
        return NULL;

    UniqueProcessId = objectEntry->ClientId.UniqueProcess;

    //
    // Id + Name
    //
    Length = 32;
    if (objectEntry->ImageName.Length) {
        Length += objectEntry->ImageName.Length;
    }
    else {
        if (UniqueProcessId == 0) {
            Length += T_IDLE_PROCESS_LENGTH;
        }
    }

    RtlSecureZeroMemory(&subitems, sizeof(subitems));

    Caption = (PWSTR)supHeapAlloc(Length);
    if (Caption) {

        PtrString = _strcat(Caption, TEXT("["));
        ultostr(HandleToULong(UniqueProcessId), PtrString);
        _strcat(Caption, TEXT("]"));

        _strcat(Caption, TEXT(" "));

        if (UniqueProcessId == 0) {
            _strcat(Caption, T_IDLE_PROCESS);
        }
        else {
            if (objectEntry->ImageName.Buffer) {
                _strcat(Caption, objectEntry->ImageName.Buffer);
            }
            else {
                _strcat(Caption, T_Unknown);
            }
        }
    }

    //
    // EPROCESS value (can be NULL)
    //
    szEPROCESS[0] = 0;
    if (ObjectAddress) {
        szEPROCESS[0] = L'0';
        szEPROCESS[1] = L'x';
        u64tohex(ObjectAddress, &szEPROCESS[2]);
    }

    subitems.UserParam = (PVOID)objectEntry;
    subitems.Count = 2;
    subitems.Text[0] = szEPROCESS;
    subitems.Text[1] = T_EmptyString;

    //
    // Colors (set order is sensitive).
    //

    //
    // 1. Services.
    //
    if (ProcessHandle) {
        ProcessSid = supQueryProcessSid(ProcessHandle);
    }

    if (ServicesList) {

        if (PsListProcessInServicesList(UniqueProcessId, ServicesList) ||
            ((ProcessSid) && RtlEqualSid(&SidLocalService, ProcessSid)))
        {
            subitems.ColorFlags = TLF_BGCOLOR_SET;
            subitems.BgColor = 0xd0d0ff;
        }

    }

    //
    // 2. Current user process.
    //
    if (ProcessSid && OurSid) {
        if (RtlEqualSid(OurSid, ProcessSid)) {
            subitems.ColorFlags = TLF_BGCOLOR_SET;
            subitems.BgColor = 0xffd0d0;
        }
    }

    //
    // 3. Store process.
    // 4. Protected process.
    //
    if (ProcessHandle) {

        if (g_ExtApiSet.IsImmersiveProcess) {
            if (g_ExtApiSet.IsImmersiveProcess(ProcessHandle)) {
                subitems.ColorFlags = TLF_BGCOLOR_SET;
                subitems.BgColor = 0xeaea00;
            }
        }

        exbi.Size = sizeof(PROCESS_EXTENDED_BASIC_INFORMATION);
        if (NT_SUCCESS(NtQueryInformationProcess(ProcessHandle, ProcessBasicInformation,
            &exbi, sizeof(exbi), &r)))
        {
            if (exbi.IsProtectedProcess) {
                subitems.ColorFlags = TLF_BGCOLOR_SET;
                subitems.BgColor = 0xe6ffe6;
            }
        }

    }

    //
    // User.
    //
    if (ProcessSid && PolicyHandle) {

        if (supLookupSidUserAndDomainEx(ProcessSid, PolicyHandle, &UserName)) {
            subitems.Text[1] = UserName;
        }
        supHeapFree(ProcessSid);
    }

    hTreeItem = supTreeListAddItem(
        PsDlgContext.TreeList,
        RootItem,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        Caption,
        &subitems);

    if (UserName)
        supHeapFree(UserName);
    if (Caption)
        supHeapFree(Caption);

    return hTreeItem;
}

typedef BOOL(CALLBACK* FINDITEMCALLBACK)(
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
    TL_SUBITEMS_FIXED* subitems = NULL;
    TVITEMEX           itemex;

    PROP_UNNAMED_OBJECT_INFO* Entry;

    RtlSecureZeroMemory(&itemex, sizeof(itemex));
    itemex.hItem = htItem;
    TreeList_GetTreeItem(TreeList, &itemex, &subitems);

    if (subitems) {
        if (subitems->UserParam == NULL)
            return FALSE;

        Entry = (PROP_UNNAMED_OBJECT_INFO*)subitems->UserParam;
        return (ParentProcessId == Entry->ClientId.UniqueProcess);
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

/*
* PsListGetThreadStateAsString
*
* Purpose:
*
* Return thread state string description.
*
*/
LPWSTR PsListGetThreadStateAsString(
    _In_ THREAD_STATE ThreadState,
    _In_ KWAIT_REASON WaitReason,
    _In_ LPWSTR StateBuffer)
{
    LPWSTR lpState = T_Unknown;
    LPWSTR lpWaitReason = T_Unknown;

    if (ThreadState == StateWait) {

        _strcpy(StateBuffer, TEXT("Wait:"));

#pragma warning(push)
#pragma warning (disable: 33010) // No.
        if (WaitReason < MAX_KNOWN_WAITREASON)
            lpWaitReason = T_WAITREASON[WaitReason];
#pragma warning(pop)

        _strcat(StateBuffer, lpWaitReason);
    }
    else {


        switch (ThreadState) {
        case StateInitialized:
            lpState = TEXT("Initiailized");
            break;
        case StateReady:
            lpState = TEXT("Ready");
            break;
        case StateRunning:
            lpState = TEXT("Running");
            break;
        case StateStandby:
            lpState = TEXT("Standby");
            break;
        case StateTerminated:
            lpState = TEXT("Terminated");
            break;
        case StateTransition:
            lpState = TEXT("Transition");
            break;
        case StateUnknown:
        default:
            break;
        }

        _strcpy(StateBuffer, lpState);
    }
    return StateBuffer;
}

/*
* CreateThreadListProc
*
* Purpose:
*
* Build and output process threads list.
*
*/
DWORD WINAPI CreateThreadListProc(
    _In_ PROP_UNNAMED_OBJECT_INFO* ObjectEntry
)
{
    INT ItemIndex;
    ULONG i, ThreadCount, ErrorCount = 0;
    HANDLE UniqueProcessId;
    PVOID ProcessList = NULL;
    PSYSTEM_PROCESSES_INFORMATION Process;
    PSYSTEM_THREAD_INFORMATION Thread;
    PRTL_PROCESS_MODULES pModules = NULL;
    PSYSTEM_HANDLE_INFORMATION_EX SortedHandleList = NULL;

    PROP_UNNAMED_OBJECT_INFO* objectEntry, * threadEntry;
    OBEX_THREAD_LOOKUP_ENTRY* stl = NULL, * stlptr;

    LVITEM lvitem;
    WCHAR szBuffer[MAX_PATH];

    ULONG_PTR startAddress = 0, objectAddress = 0;

    DWORD dwWaitResult;

    __try {

        dwWaitResult = WaitForSingleObject(g_PsListWait, INFINITE);
        if (dwWaitResult == WAIT_OBJECT_0) {

            supSetWaitCursor(TRUE);

            ListView_DeleteAllItems(PsDlgContext.ListView);

            UniqueProcessId = ObjectEntry->ClientId.UniqueProcess;

            //
            // Refresh thread list.
            //
            ProcessList = supGetSystemInfo(SystemProcessInformation, NULL);
            if (ProcessList == NULL)
                __leave;

            //
            // Leave if process died.
            //
            if (!supQueryProcessEntryById(UniqueProcessId, ProcessList, &Process))
                __leave;

            pModules = (PRTL_PROCESS_MODULES)supGetLoadedModulesList(NULL);

            ThreadCount = Process->ThreadCount;
            stl = (OBEX_THREAD_LOOKUP_ENTRY*)supHeapAlloc(ThreadCount * sizeof(OBEX_THREAD_LOOKUP_ENTRY));
            if (stl == NULL)
                __leave;

            stlptr = stl;

            for (i = 0, Thread = Process->Threads;
                i < ThreadCount;
                i++, Thread++, stlptr++)
            {
                objectEntry = PsxAllocateUnnamedObjectEntry(Thread, ObjectTypeThread);
                if (objectEntry) {

                    stlptr->EntryPtr = (PVOID)objectEntry;

                    if (!NT_SUCCESS(supOpenThread(&Thread->ClientId,
                        THREAD_QUERY_INFORMATION,
                        &stlptr->hThread)))
                    {
                        supOpenThread(&Thread->ClientId,
                            THREAD_QUERY_LIMITED_INFORMATION,
                            &stlptr->hThread);
                    }
                }
            }

            supHeapFree(ProcessList);
            ProcessList = NULL;

            SortedHandleList = supHandlesCreateFilteredAndSortedList(GetCurrentProcessId(), FALSE);
            stlptr = stl;

            supListViewEnableRedraw(PsDlgContext.ListView, FALSE);

            for (i = 0; i < ThreadCount; i++, stlptr++) {

                threadEntry = (PROP_UNNAMED_OBJECT_INFO*)stlptr->EntryPtr;

                //
                // TID
                //               
                szBuffer[0] = 0;
                ultostr(HandleToULong(threadEntry->ClientId.UniqueThread), szBuffer);

                RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
                lvitem.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
                lvitem.iItem = MAXINT;
                lvitem.iImage = I_IMAGENONE;
                lvitem.pszText = szBuffer;
                lvitem.cchTextMax = MAX_PATH;
                lvitem.lParam = (LPARAM)threadEntry;
                ItemIndex = ListView_InsertItem(PsDlgContext.ListView, &lvitem);

                //
                // Priority
                //
                szBuffer[0] = 0;
                ultostr(threadEntry->ThreadInformation.Priority, szBuffer);

                lvitem.mask = LVIF_TEXT;
                lvitem.iSubItem++;
                lvitem.pszText = szBuffer;
                lvitem.iItem = ItemIndex;
                ListView_SetItem(PsDlgContext.ListView, &lvitem);

                //
                // State
                //
                lvitem.iSubItem++;
                lvitem.pszText = PsListGetThreadStateAsString(
                    threadEntry->ThreadInformation.State,
                    threadEntry->ThreadInformation.WaitReason, szBuffer);

                ListView_SetItem(PsDlgContext.ListView, &lvitem);

                // Query thread specific information - object and win32 start address (need elevation).
                startAddress = 0;
                objectAddress = 0;

                if (stlptr->hThread) {

                    if (!supQueryThreadWin32StartAddress(
                        stlptr->hThread,
                        &startAddress))
                    {
                        ErrorCount += 1;
                    }

                    if (SortedHandleList) {

                        if (!supHandlesQueryObjectAddress(
                            SortedHandleList,
                            stlptr->hThread,
                            &objectAddress))
                        {
                            ErrorCount += 1;
                        }

                    }
                    else {
                        ErrorCount += 1;
                    }

                    NtClose(stlptr->hThread);
                }

                if (startAddress == 0)
                    startAddress = (ULONG_PTR)threadEntry->ThreadInformation.StartAddress;

                //
                // ETHREAD
                //
                szBuffer[0] = TEXT('0');
                szBuffer[1] = TEXT('x');
                szBuffer[2] = 0;
                u64tohex(objectAddress, &szBuffer[2]);

                lvitem.iSubItem++;
                lvitem.pszText = szBuffer;
                ListView_SetItem(PsDlgContext.ListView, &lvitem);

                //
                // StartAddress (either Win32StartAddress if possible or StartAddress from NtQSI)
                //
                szBuffer[0] = TEXT('0');
                szBuffer[1] = TEXT('x');
                szBuffer[2] = 0;

                u64tohex((ULONG_PTR)startAddress, &szBuffer[2]);

                lvitem.iSubItem++;
                lvitem.pszText = szBuffer;
                ListView_SetItem(PsDlgContext.ListView, &lvitem);

                //
                // Module (for system threads)
                //
                szBuffer[0] = 0;
                if (startAddress > g_kdctx.SystemRangeStart && pModules) {
                    if (!ntsupFindModuleNameByAddress(
                        pModules,
                        (PVOID)startAddress,
                        szBuffer,
                        MAX_PATH))
                    {
                        _strcpy(szBuffer, T_Unknown);
                    }
                }
                lvitem.iSubItem++;
                lvitem.pszText = szBuffer;
                ListView_SetItem(PsDlgContext.ListView, &lvitem);
            }

            if (ErrorCount != 0) {
                _strcpy(szBuffer, TEXT("Some queries for threads information are failed"));
            }
            else {
                _strcpy(szBuffer, TEXT("All queries for threads information are succeeded"));
            }

            supStatusBarSetText(PsDlgContext.StatusBar, 2, (LPWSTR)&szBuffer);

            ListView_SortItemsEx(
                PsDlgContext.ListView,
                PsListCompareFunc,
                PsDlgContext.lvColumnToSort);

            supListViewEnableRedraw(PsDlgContext.ListView, TRUE);

        }
    }
    __finally {

        if (AbnormalTermination())
            supReportAbnormalTermination(__FUNCTIONW__);

        if (pModules) supHeapFree(pModules);
        if (stl) supHeapFree(stl);

        supHandlesFreeList(SortedHandleList);

        if (ProcessList) supHeapFree(ProcessList);

        supSetWaitCursor(FALSE);

        ReleaseMutex(g_PsListWait);
    }

    return 0;
}

/*
* CreateProcessListProc
*
* Purpose:
*
* Build and output process tree list.
*
*/
DWORD WINAPI CreateProcessListProc(
    PVOID Parameter
)
{
    BOOL bRefresh = (BOOL)PtrToInt(Parameter);
    DWORD ServiceEnumType, dwWaitResult;
    ULONG NextEntryDelta = 0, nProcesses = 0, nThreads = 0;

    HTREEITEM ViewRootHandle;

    ULONG_PTR ObjectAddress;

    HANDLE ProcessHandle = NULL;
    PVOID InfoBuffer = NULL;
    PSYSTEM_HANDLE_INFORMATION_EX SortedHandleList = NULL;
    PSID OurSid = NULL;
    PWSTR lpErrorMsg;

    LSA_HANDLE lsaPolicyHandle = NULL;

    SCMDB ServicesList;

    WCHAR szBuffer[100];

    union {
        PSYSTEM_PROCESSES_INFORMATION ProcessEntry;
        PBYTE ListRef;
    } List;

    ServicesList.Entries = NULL;
    ServicesList.NumberOfEntries = 0;

    __try {
        dwWaitResult = WaitForSingleObject(g_PsListWait, INFINITE);
        if (dwWaitResult == WAIT_OBJECT_0) {

            InitializeListHead(&g_PsListHead);
            InterlockedIncrement((PLONG)&g_DialogRefresh);

            supSetWaitCursor(TRUE);

            TreeList_ClearTree(PsDlgContext.TreeList);
            ListView_DeleteAllItems(PsDlgContext.ListView);

            if (bRefresh) {
                RtlDestroyHeap(g_PsListHeap);
                g_PsListHeap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
                if (g_PsListHeap == NULL) {
                    lpErrorMsg = TEXT("Could not allocate heap for process enumeration!");
                    supStatusBarSetText(PsDlgContext.StatusBar, 2, lpErrorMsg);
                    __leave;
                }
            }

            ServiceEnumType = SERVICE_WIN32 | SERVICE_INTERACTIVE_PROCESS;

            if (g_NtBuildNumber >= NT_WIN10_THRESHOLD1) {
                ServiceEnumType |= SERVICE_USER_SERVICE | SERVICE_USERSERVICE_INSTANCE;
            }

            if (!supCreateSCMSnapshot(ServiceEnumType, &ServicesList)) {
                lpErrorMsg = TEXT("Error building services list!");
                supStatusBarSetText(PsDlgContext.StatusBar, 2, lpErrorMsg);
                __leave;
            }

            RtlQuickSort(ServicesList.Entries,
                ServicesList.NumberOfEntries,
                sizeof(ENUM_SERVICE_STATUS_PROCESS),
                PsxSCMLookupCallback);

            InfoBuffer = supGetSystemInfo(SystemProcessInformation, NULL);
            if (InfoBuffer == NULL) {
                lpErrorMsg = TEXT("Error query process list!");
                supStatusBarSetText(PsDlgContext.StatusBar, 2, lpErrorMsg);
                __leave;
            }

            if (!supPHLCreate(&g_PsListHead,
                (PBYTE)InfoBuffer,
                &nProcesses,
                &nThreads))
            {
                lpErrorMsg = TEXT("Error building handle list!");
                supStatusBarSetText(PsDlgContext.StatusBar, 2, lpErrorMsg);
                __leave;
            }

            //
            // Show processes/threads count
            //
            _strcpy(szBuffer, TEXT("Processes: "));
            ultostr(nProcesses, _strend(szBuffer));
            supStatusBarSetText(PsDlgContext.StatusBar, 0, (LPWSTR)&szBuffer);

            _strcpy(szBuffer, TEXT("Threads: "));
            ultostr(nThreads, _strend(szBuffer));
            supStatusBarSetText(PsDlgContext.StatusBar, 1, (LPWSTR)&szBuffer);

            SortedHandleList = supHandlesCreateFilteredAndSortedList(GetCurrentProcessId(), FALSE);

            OurSid = supQueryProcessSid(NtCurrentProcess());

            lsaPolicyHandle = NULL;
            supLsaOpenMachinePolicy(POLICY_LOOKUP_NAMES, &lsaPolicyHandle);

            NextEntryDelta = 0;
            ViewRootHandle = NULL;
            List.ListRef = (PBYTE)InfoBuffer;

            do {
                List.ListRef += NextEntryDelta;
                NextEntryDelta = List.ProcessEntry->NextEntryDelta;

                if (List.ProcessEntry->UniqueProcessId == 0)
                    continue;

                ViewRootHandle = FindParentItem(PsDlgContext.TreeList,
                    List.ProcessEntry->InheritedFromUniqueProcessId);

                ObjectAddress = 0;
                ProcessHandle = supPHLGetEntry(&g_PsListHead, List.ProcessEntry->UniqueProcessId);

                if (SortedHandleList && ProcessHandle) {
                    supHandlesQueryObjectAddress(SortedHandleList,
                        ProcessHandle,
                        &ObjectAddress);
                }

                if (ViewRootHandle == NULL) {
                    ViewRootHandle = AddProcessEntryTreeList(NULL,
                        ProcessHandle,
                        (PVOID)List.ProcessEntry,
                        ObjectAddress,
                        &ServicesList,
                        OurSid,
                        lsaPolicyHandle);
                }
                else {
                    AddProcessEntryTreeList(ViewRootHandle,
                        ProcessHandle,
                        (PVOID)List.ProcessEntry,
                        ObjectAddress,
                        &ServicesList,
                        OurSid,
                        lsaPolicyHandle);
                }

                if (ProcessHandle) {
                    NtClose(ProcessHandle);
                }

            } while (NextEntryDelta);

            if (lsaPolicyHandle) LsaClose(lsaPolicyHandle);

        }
    }
    __finally {

        if (AbnormalTermination())
            supReportAbnormalTermination(__FUNCTIONW__);

        if (OurSid) supHeapFree(OurSid);
        supFreeSCMSnapshot(&ServicesList);
        if (InfoBuffer) supHeapFree(InfoBuffer);

        supHandlesFreeList(SortedHandleList);
        supPHLFree(&g_PsListHead, FALSE);

        InterlockedDecrement((PLONG)&g_DialogRefresh);

        supSetWaitCursor(FALSE);

        ReleaseMutex(g_PsListWait);
    }
    return 0;
}

/*
* CreateObjectList
*
* Purpose:
*
* Build and output process/threads list.
*
*/
VOID CreateObjectList(
    _In_ BOOL ListThreads,
    _In_opt_ PVOID ThreadParam
)
{
    DWORD ThreadId;
    HANDLE hThread;
    LPTHREAD_START_ROUTINE lpThreadRoutine;

    if (g_DialogQuit)
        return;

    if (ListThreads)
        lpThreadRoutine = (LPTHREAD_START_ROUTINE)CreateThreadListProc;
    else
        lpThreadRoutine = (LPTHREAD_START_ROUTINE)CreateProcessListProc;

    hThread = CreateThread(NULL,
        0,
        lpThreadRoutine,
        ThreadParam,
        0,
        &ThreadId);

    if (hThread) {
        CloseHandle(hThread);
    }
}

/*
* PsListHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for dialog listview.
*
*/
INT_PTR PsListHandleNotify(
    _In_ HWND hwndDlg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    LPNMHDR nhdr = (LPNMHDR)lParam;
    INT     nImageIndex;

    TVHITTESTINFO   hti;
    POINT pt;

    HWND TreeControl;

    PROP_UNNAMED_OBJECT_INFO* ObjectEntry;

    UNREFERENCED_PARAMETER(hwndDlg);

    if ((g_DialogRefresh) || (nhdr == NULL) || (g_DialogQuit))
        return 0;

    TreeControl = (HWND)TreeList_GetTreeControlWindow(PsDlgContext.TreeList);

    if (nhdr->hwndFrom == PsDlgContext.ListView) {

        switch (nhdr->code) {

        case NM_DBLCLK:
            ObjectEntry = PsListGetObjectEntry(FALSE, NULL);
            if (ObjectEntry) {
                PsListHandleObjectProp(FALSE, ObjectEntry);
            }

            return 1;

        case LVN_COLUMNCLICK:
            PsDlgContext.bInverseSort = !PsDlgContext.bInverseSort;
            PsDlgContext.lvColumnToSort = ((NMLISTVIEW*)lParam)->iSubItem;

            ListView_SortItemsEx(PsDlgContext.ListView, &PsListCompareFunc, (LPARAM)PsDlgContext.lvColumnToSort);

            nImageIndex = ImageList_GetImageCount(g_ListViewImages);
            if (PsDlgContext.bInverseSort)
                nImageIndex -= 2;
            else
                nImageIndex -= 1;

            supUpdateLvColumnHeaderImage(
                PsDlgContext.ListView,
                PsDlgContext.lvColumnCount,
                PsDlgContext.lvColumnToSort,
                nImageIndex);

            return 1;

        default:
            break;
        }

    }
    else if (nhdr->hwndFrom == TreeControl) {

        switch (nhdr->code) {

        case NM_DBLCLK:
#pragma warning(push)
#pragma warning(disable: 26454)
            nhdr->code = NM_RETURN;
#pragma warning(pop)
            return PostMessage(hwndDlg, WM_NOTIFY, wParam, lParam);

        case NM_RETURN:
            GetCursorPos(&pt);
            hti.pt = pt;
            ScreenToClient(TreeControl, &hti.pt);
            if (TreeView_HitTest(TreeControl, &hti) &&
                (hti.flags & (TVHT_ONITEM | TVHT_ONITEMRIGHT)))
            {
                ObjectEntry = PsListGetObjectEntry(TRUE, hti.hItem);
                if (ObjectEntry) {
                    PsListHandleObjectProp(TRUE, ObjectEntry);
                }
            }
            return 1;

        case TVN_SELCHANGED:
            ObjectEntry = PsListGetObjectEntry(TRUE, NULL);
            if (ObjectEntry) {
                CreateObjectList(TRUE, ObjectEntry);
            }
            return 1;

        default:
            break;
        }

    }

    return 0;
}

/*
* PsListHandleThreadRefresh
*
* Purpose:
*
* Refresh thread list handler.
*
*/
VOID PsListHandleThreadRefresh(
    VOID
)
{
    PROP_UNNAMED_OBJECT_INFO* ObjectEntry;

    ObjectEntry = PsListGetObjectEntry(TRUE, NULL);
    if (ObjectEntry) {
        CreateObjectList(TRUE, ObjectEntry);
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
    INT dy;
    UINT uCommandId;
    RECT crc;
    INT mark;
    HWND TreeListControl, FocusWindow;

    if (uMsg == g_WinObj.SettingsChangeMessage) {
        extrasHandleSettingsChange(&PsDlgContext);
        return TRUE;
    }

    switch (uMsg) {

    case WM_CONTEXTMENU:

        RtlSecureZeroMemory(&crc, sizeof(crc));

        TreeListControl = TreeList_GetTreeControlWindow(PsDlgContext.TreeList);

        if ((HWND)wParam == TreeListControl) {
            GetCursorPos((LPPOINT)&crc);
            PsListHandlePopupMenu(hwndDlg, (LPPOINT)&crc, ID_OBJECT_COPY, ID_VIEW_REFRESH, TRUE);
        }

        if ((HWND)wParam == PsDlgContext.ListView) {

            mark = ListView_GetSelectionMark(PsDlgContext.ListView);

            if (lParam == MAKELPARAM(-1, -1)) {
                ListView_GetItemRect(PsDlgContext.ListView, mark, &crc, TRUE);
                crc.top = crc.bottom;
                ClientToScreen(PsDlgContext.ListView, (LPPOINT)&crc);
            }
            else
                GetCursorPos((LPPOINT)&crc);

            PsListHandlePopupMenu(hwndDlg, (LPPOINT)&crc, ID_OBJECT_COPY + 1, ID_VIEW_REFRESH + 1, FALSE);
        }

        break;

    case WM_NOTIFY:
        return PsListHandleNotify(hwndDlg, wParam, lParam);

    case WM_COMMAND:

        uCommandId = GET_WM_COMMAND_ID(wParam, lParam);

        switch (uCommandId) {

        case IDCANCEL:
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            return TRUE;
        
        case ID_OBJECT_COPY:
            supCopyTreeListSubItemValue(PsDlgContext.TreeList, 0);
            break;

        case ID_OBJECT_COPY + 1:            
            supListViewCopyItemValueToClipboard(PsDlgContext.ListView,
                PsDlgContext.lvItemHit,
                PsDlgContext.lvColumnHit);

            break;

        case ID_VIEW_REFRESH:
        case ID_VIEW_REFRESH + 1:

            FocusWindow = GetFocus();
            TreeListControl = TreeList_GetTreeControlWindow(PsDlgContext.TreeList);

            if (FocusWindow == TreeListControl) {
                CreateObjectList(FALSE, IntToPtr(TRUE));
            }
            else if (FocusWindow == PsDlgContext.ListView) {
                PsListHandleThreadRefresh();
            }
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
            supSetMinMaxTrackSize((PMINMAXINFO)lParam,
                PSLISTDLG_TRACKSIZE_MIN_X,
                PSLISTDLG_TRACKSIZE_MIN_Y,
                TRUE);
        }
        break;

    case WM_SIZE:
        return PsListDialogResize();

    case WM_LBUTTONDOWN:
        SetCapture(hwndDlg);
        y_capture_pos = (int)(short)HIWORD(lParam);
        break;

    case WM_LBUTTONUP:
        ReleaseCapture();
        break;

    case WM_MOUSEMOVE:

        if (wParam & MK_LBUTTON) {
            dy = (int)(short)HIWORD(lParam) - y_capture_pos;
            if (dy != 0) {
                y_capture_pos = (int)(short)HIWORD(lParam);
                y_splitter_pos += dy;
                if (y_splitter_pos < Y_SPLITTER_MIN)
                {
                    y_splitter_pos = Y_SPLITTER_MIN;
                    y_capture_pos = Y_SPLITTER_MIN;
                }

                if (y_splitter_pos > y_splitter_max)
                {
                    y_splitter_pos = y_splitter_max;
                    y_capture_pos = y_splitter_max;
                }
                SendMessage(hwndDlg, WM_SIZE, 0, 0);
            }
        }

        break;

    case WM_CLOSE:
        InterlockedAdd((PLONG)&g_DialogQuit, 1);
        if (g_PsListWait) {
            CloseHandle(g_PsListWait);
            g_PsListWait = NULL;
        }

        DestroyWindow(PsDlgContext.TreeList);
        DestroyWindow(hwndDlg);
        g_WinObj.AuxDialogs[wobjPsListDlgId] = NULL;
        if (g_PsListHeap) {
            RtlDestroyHeap(g_PsListHeap);
            g_PsListHeap = NULL;
        }
        return TRUE;
    }

    return DefDlgProc(hwndDlg, uMsg, wParam, lParam);
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
    LONG_PTR    wndStyles;
    HDITEM      hdritem;
    WNDCLASSEX  wincls;

    INT SbParts[] = { 160, 320, -1 };

    INT iImage = ImageList_GetImageCount(g_ListViewImages) - 1;
    LVCOLUMNS_DATA columnData[] =
    {
        { L"TID", 60, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,  iImage },
        { L"Priority", 100, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,  I_IMAGENONE },
        { L"State", 150, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,  I_IMAGENONE },
        { L"Object", 150, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,  I_IMAGENONE },
        { L"StartAddress", 140, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,  I_IMAGENONE },
        { L"Module(System threads)", 200, LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,  I_IMAGENONE }
    };

    //
    // Allow only one dialog.
    //
    ENSURE_DIALOG_UNIQUE_WITH_RESTORE(g_WinObj.AuxDialogs[wobjPsListDlgId]);

    RtlSecureZeroMemory(&wincls, sizeof(wincls));
    wincls.cbSize = sizeof(WNDCLASSEX);
    wincls.lpfnWndProc = &PsListDialogProc;
    wincls.cbWndExtra = DLGWINDOWEXTRA;
    wincls.hInstance = g_WinObj.hInstance;
    wincls.hCursor = (HCURSOR)LoadImage(NULL,
        MAKEINTRESOURCE(OCR_SIZENS), IMAGE_CURSOR, 0, 0, LR_SHARED);
    wincls.hIcon = (HICON)LoadImage(g_WinObj.hInstance,
        MAKEINTRESOURCE(IDI_ICON_MAIN), IMAGE_ICON, 0, 0, LR_SHARED);
    wincls.lpszClassName = WINOBJEX64_PSLISTCLASS;

    RegisterClassEx(&wincls);

    RtlSecureZeroMemory(&PsDlgContext, sizeof(PsDlgContext));
    PsDlgContext.hwndDlg = CreateDialogParam(
        g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_PSLIST),
        hwndParent,
        NULL,
        0);

    if (PsDlgContext.hwndDlg == NULL)
        return;

    if (g_kdctx.IsFullAdmin == FALSE) {
        SetWindowText(PsDlgContext.hwndDlg, TEXT("Processes (Non elevated mode, some information maybe unavailable)"));
    }

    g_WinObj.AuxDialogs[wobjPsListDlgId] = PsDlgContext.hwndDlg;

    PsDlgContext.ListView = GetDlgItem(PsDlgContext.hwndDlg, IDC_PSLIST_LISTVIEW);
    PsDlgContext.StatusBar = GetDlgItem(PsDlgContext.hwndDlg, IDC_PSLIST_STATUSBAR);
    PsDlgContext.TreeList = GetDlgItem(PsDlgContext.hwndDlg, IDC_PSLIST_TREELIST);

    SendMessage(PsDlgContext.StatusBar, SB_SETPARTS, 3, (LPARAM)&SbParts);

    if (PsDlgContext.ListView) {

        supSetListViewSettings(PsDlgContext.ListView,
            LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP | LVS_EX_DOUBLEBUFFER,
            FALSE,
            TRUE,
            g_ListViewImages,
            LVSIL_SMALL);

        //
        // And columns and remember their count.
        //
        PsDlgContext.lvColumnCount = supAddLVColumnsFromArray(
            PsDlgContext.ListView,
            columnData,
            RTL_NUMBER_OF(columnData));
    }

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

        wndStyles = GetWindowLongPtr(PsDlgContext.TreeList, GWL_STYLE);
        SetWindowLongPtr(PsDlgContext.TreeList, GWL_STYLE, wndStyles | TLSTYLE_LINKLINES);
    }

    PsListDialogResize();

    g_DialogQuit = 0;
    g_DialogRefresh = 0;
    g_PsListWait = CreateMutex(NULL, FALSE, NULL);
    if (g_PsListWait) {
        g_PsListHeap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
        if (g_PsListHeap) {
            CreateObjectList(FALSE, NULL);
        }
    }
}
