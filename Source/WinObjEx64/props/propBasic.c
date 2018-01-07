/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       PROPBASIC.C
*
*  VERSION:     1.52
*
*  DATE:        08 Jan 2018
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "propDlg.h"
#include "propBasicConsts.h"

/*
* propSetDefaultInfo
*
* Purpose:
*
* Set information values for Basic page window, obtained from NtQueryObject calls
*
* ObjectBasicInformation and ObjectTypeInformation used
*
*/
VOID propSetDefaultInfo(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg,
    _In_ HANDLE hObject
)
{
    BOOL     cond = FALSE;
    INT      i;
    HWND     hwndCB;
    NTSTATUS status;
    ULONG    bytesNeeded;
    WCHAR    szBuffer[100];

    OBJECT_BASIC_INFORMATION obi;
    POBJECT_TYPE_INFORMATION TypeInfo = NULL;

    if ((hObject == NULL) || (Context == NULL)) {
        return;
    }

    //
    // Query object basic information.
    //
    RtlSecureZeroMemory(&obi, sizeof(obi));
    status = NtQueryObject(hObject, ObjectBasicInformation, &obi,
        sizeof(OBJECT_BASIC_INFORMATION), &bytesNeeded);

    if (NT_SUCCESS(status)) {

        //Reference Count
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        u64tostr(obi.PointerCount, szBuffer);
        SetDlgItemText(hwndDlg, ID_OBJECT_REFC, szBuffer);

        //Handle Count
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        u64tostr(obi.HandleCount, szBuffer);
        SetDlgItemText(hwndDlg, ID_OBJECT_HANDLES, szBuffer);

        //NonPagedPoolCharge
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        u64tostr(obi.NonPagedPoolCharge, szBuffer);
        SetDlgItemText(hwndDlg, ID_OBJECT_NP_CHARGE, szBuffer);

        //PagedPoolCharge
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        u64tostr(obi.PagedPoolCharge, szBuffer);
        SetDlgItemText(hwndDlg, ID_OBJECT_PP_CHARGE, szBuffer);

        //Attributes
        hwndCB = GetDlgItem(hwndDlg, IDC_OBJECT_FLAGS);
        if (hwndCB) {
            SendMessage(hwndCB, CB_RESETCONTENT, (WPARAM)0, (LPARAM)0);
            EnableWindow(hwndCB, (obi.Attributes > 0) ? TRUE : FALSE);
            if (obi.Attributes != 0) {
                for (i = 0; i < 8; i++) {
                    if (GET_BIT(obi.Attributes, i)) SendMessage(hwndCB, CB_ADDSTRING,
                        (WPARAM)0, (LPARAM)T_ObjectFlags[i]);
                }
                SendMessage(hwndCB, CB_SETCURSEL, (WPARAM)0, (LPARAM)0);
            }
        }
    }

    //
    // Set flag bit for next usage on Type page.
    //
    do {

        bytesNeeded = 0;
        status = NtQueryObject(hObject, ObjectTypeInformation, NULL, 0, &bytesNeeded);
        if (bytesNeeded == 0) {
            SetLastError(RtlNtStatusToDosError(status));
            break;
        }

        TypeInfo = supHeapAlloc(bytesNeeded + sizeof(ULONG_PTR));
        if (TypeInfo == NULL)
            break;

        status = NtQueryObject(hObject, ObjectTypeInformation, TypeInfo, bytesNeeded, &bytesNeeded);
        if (NT_SUCCESS(status)) {
            if (TypeInfo->SecurityRequired) {
                SET_BIT(Context->ObjectFlags, 3);
            }
            if (TypeInfo->MaintainHandleCount) {
                SET_BIT(Context->ObjectFlags, 4);
            }
        }
        else {
            SetLastError(RtlNtStatusToDosError(status));
        }

    } while (cond);

    if (TypeInfo) {
        supHeapFree(TypeInfo);
    }
}

/*
* propBasicQueryDirectory
*
* Purpose:
*
* Set information values for Directory object type
*
* No Additional info required
*
*/
VOID propBasicQueryDirectory(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    HANDLE hObject;

    if (Context == NULL) {
        return;
    }

    //
    // Open object directory.
    //
    hObject = NULL;
    if (!propOpenCurrentObject(Context, &hObject, DIRECTORY_QUERY)) {
        return;
    }

    propSetDefaultInfo(Context, hwndDlg, hObject);
    NtClose(hObject);
}

/*
* propBasicQuerySemaphore
*
* Purpose:
*
* Set information values for Semaphore object type
*
* If ExtendedInfoAvailable is FALSE then it calls propSetDefaultInfo to set Basic page properties
*
*/
VOID propBasicQuerySemaphore(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg,
    _In_ BOOL ExtendedInfoAvailable
)
{
    NTSTATUS  status;
    ULONG     bytesNeeded;
    HANDLE    hObject;
    WCHAR	  szBuffer[MAX_PATH + 1];

    SEMAPHORE_BASIC_INFORMATION sbi;

    SetDlgItemText(hwndDlg, ID_SEMAPHORECURRENT, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_SEMAPHOREMAXCOUNT, T_CannotQuery);

    if (Context == NULL) {
        return;
    }

    //
    // Open semaphore object.
    //
    hObject = NULL;
    if (!propOpenCurrentObject(Context, &hObject, SEMAPHORE_QUERY_STATE)) {
        return;
    }

    RtlSecureZeroMemory(&sbi, sizeof(SEMAPHORE_BASIC_INFORMATION));
    status = NtQuerySemaphore(hObject, SemaphoreBasicInformation, &sbi,
        sizeof(SEMAPHORE_BASIC_INFORMATION), &bytesNeeded);
    if (NT_SUCCESS(status)) {

        //Current count
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        ultostr(sbi.CurrentCount, szBuffer);
        SetDlgItemText(hwndDlg, ID_SEMAPHORECURRENT, szBuffer);

        //Maximum count
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        ultostr(sbi.MaximumCount, szBuffer);
        SetDlgItemText(hwndDlg, ID_SEMAPHOREMAXCOUNT, szBuffer);
    }

    //
    // Query object basic and type info if needed.
    //
    if (ExtendedInfoAvailable == FALSE) {
        propSetDefaultInfo(Context, hwndDlg, hObject);
    }
    NtClose(hObject);
}

/*
* propBasicQueryIoCompletion
*
* Purpose:
*
* Set information values for IoCompletion object type
*
* If ExtendedInfoAvailable is FALSE then it calls propSetDefaultInfo to set Basic page properties
*
*/
VOID propBasicQueryIoCompletion(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg,
    _In_ BOOL ExtendedInfoAvailable
)
{
    NTSTATUS status;
    ULONG    bytesNeeded;
    HANDLE   hObject;

    IO_COMPLETION_BASIC_INFORMATION iobi;

    SetDlgItemText(hwndDlg, ID_IOCOMPLETIONSTATE, T_CannotQuery);

    if (Context == NULL) {
        return;
    }

    //
    // Open IoCompletion object.
    //
    hObject = NULL;
    if (!propOpenCurrentObject(Context, &hObject, IO_COMPLETION_QUERY_STATE)) {
        return;
    }

    RtlSecureZeroMemory(&iobi, sizeof(IO_COMPLETION_BASIC_INFORMATION));
    status = NtQueryIoCompletion(hObject, IoCompletionBasicInformation, &iobi,
        sizeof(iobi), &bytesNeeded);

    if (NT_SUCCESS(status)) {
        SetDlgItemText(hwndDlg, ID_IOCOMPLETIONSTATE,
            (iobi.Depth > 0) ? TEXT("Signaled") : TEXT("Nonsignaled"));
    }

    //
    // Query object basic and type info if needed.
    //
    if (ExtendedInfoAvailable == FALSE) {
        propSetDefaultInfo(Context, hwndDlg, hObject);
    }
    NtClose(hObject);
}

/*
* propBasicQueryTimer
*
* Purpose:
*
* Set information values for Timer object type
*
* If ExtendedInfoAvailable is FALSE then it calls propSetDefaultInfo to set Basic page properties
*
*/
VOID propBasicQueryTimer(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg,
    _In_ BOOL ExtendedInfoAvailable
)
{
    NTSTATUS    status;
    ULONG       bytesNeeded;
    HANDLE      hObject;
    ULONGLONG   ConvertedSeconds, Hours;
    CSHORT      Minutes, Seconds;
    WCHAR       szBuffer[MAX_PATH + 1];

    TIMER_BASIC_INFORMATION tbi;

    SetDlgItemText(hwndDlg, ID_TIMERSTATE, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_TIMERREMAINING, T_CannotQuery);

    if (Context == NULL) {
        return;
    }

    //
    // Open Timer object.
    //
    hObject = NULL;
    if (!propOpenCurrentObject(Context, &hObject, TIMER_QUERY_STATE)) {
        return;
    }

    RtlSecureZeroMemory(&tbi, sizeof(TIMER_BASIC_INFORMATION));
    status = NtQueryTimer(hObject, TimerBasicInformation, &tbi,
        sizeof(TIMER_BASIC_INFORMATION), &bytesNeeded);

    if (NT_SUCCESS(status)) {

        //Timer state
        SetDlgItemText(hwndDlg, ID_TIMERSTATE,
            (tbi.TimerState) ? TEXT("Signaled") : TEXT("Nonsignaled"));

        if (tbi.TimerState != TRUE) {
            ConvertedSeconds = (tbi.RemainingTime.QuadPart / 10000000LL);
            Seconds = (CSHORT)(ConvertedSeconds % 60);
            Minutes = (CSHORT)((ConvertedSeconds / 60) % 60);
            Hours = ConvertedSeconds / 3600;

            //Timer remaining
            RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
            wsprintf(szBuffer, FORMATTED_TIME_VALUE,
                Hours,
                Minutes,
                Seconds);

            SetDlgItemText(hwndDlg, ID_TIMERREMAINING, szBuffer);
        }
    }

    //
    // Query object basic and type info if needed.
    //
    if (ExtendedInfoAvailable == FALSE) {
        propSetDefaultInfo(Context, hwndDlg, hObject);
    }
    NtClose(hObject);
}

/*
* propBasicQueryEvent
*
* Purpose:
*
* Set information values for Event object type
*
* If ExtendedInfoAvailable is FALSE then it calls propSetDefaultInfo to set Basic page properties
*
*/
VOID propBasicQueryEvent(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg,
    _In_ BOOL ExtendedInfoAvailable
)
{
    NTSTATUS status;
    ULONG    bytesNeeded;
    HANDLE   hObject;
    LPWSTR   lpInfo;
    EVENT_BASIC_INFORMATION	ebi;

    SetDlgItemText(hwndDlg, ID_EVENTTYPE, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_EVENTSTATE, T_CannotQuery);

    if (Context == NULL) {
        return;
    }

    //
    // Open Event object.
    //
    hObject = NULL;
    if (!propOpenCurrentObject(Context, &hObject, EVENT_QUERY_STATE)) {
        return;
    }

    RtlSecureZeroMemory(&ebi, sizeof(EVENT_BASIC_INFORMATION));
    status = NtQueryEvent(hObject, EventBasicInformation, &ebi,
        sizeof(EVENT_BASIC_INFORMATION), &bytesNeeded);

    if (NT_SUCCESS(status)) {

        //Event type
        switch (ebi.EventType) {
        case NotificationEvent:
            lpInfo = TEXT("Notification");
            break;
        case SynchronizationEvent:
            lpInfo = TEXT("Synchronization");
            break;
        default:
            lpInfo = T_UnknownType;
            break;
        }
        SetDlgItemText(hwndDlg, ID_EVENTTYPE, lpInfo);

        //Event state
        switch (ebi.EventState) {
        case 0:
            lpInfo = TEXT("Nonsignaled");
            break;
        case 1:
            lpInfo = TEXT("Signaled");
            break;
        default:
            lpInfo = TEXT("UnknownState");
            break;
        }
        SetDlgItemText(hwndDlg, ID_EVENTSTATE, lpInfo);
    }

    //
    // Query object basic and type info if needed.
    //
    if (ExtendedInfoAvailable == FALSE) {
        propSetDefaultInfo(Context, hwndDlg, hObject);
    }
    NtClose(hObject);
}

/*
* propBasicQuerySymlink
*
* Purpose:
*
* Set information values for SymbolicLink object type
*
* If ExtendedInfoAvailable is FALSE then it calls propSetDefaultInfo to set Basic page properties
*
*/
VOID propBasicQuerySymlink(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg,
    _In_ BOOL ExtendedInfoAvailable
)
{
    NTSTATUS    status;
    ULONG       bytesNeeded;
    HANDLE      hObject;
    LPWSTR      lpLinkTarget;
    TIME_FIELDS	SystemTime;
    WCHAR       szBuffer[MAX_PATH];

    OBJECT_BASIC_INFORMATION obi;

    SetDlgItemText(hwndDlg, ID_OBJECT_SYMLINK_TARGET, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_OBJECT_SYMLINK_CREATION, T_CannotQuery);

    if (Context == NULL) {
        return;
    }

    //
    // Open SymbolicLink object.
    //
    hObject = NULL;
    if (!propOpenCurrentObject(Context, &hObject, SYMBOLIC_LINK_QUERY)) {
        return;
    }

    //
    // Copy link target from main object list for performance reasons.
    // So we don't need to query same data again.
    //
    lpLinkTarget = Context->lpDescription;
    if (lpLinkTarget) {
        SetDlgItemText(hwndDlg, ID_OBJECT_SYMLINK_TARGET, lpLinkTarget);
    }

    //Query Link Creation Time
    RtlSecureZeroMemory(&obi, sizeof(OBJECT_BASIC_INFORMATION));

    status = NtQueryObject(hObject, ObjectBasicInformation, &obi,
        sizeof(OBJECT_BASIC_INFORMATION), &bytesNeeded);

    if (NT_SUCCESS(status)) {
        FileTimeToLocalFileTime((PFILETIME)&obi.CreationTime, (PFILETIME)&obi.CreationTime);
        RtlSecureZeroMemory(&SystemTime, sizeof(SystemTime));
        RtlTimeToTimeFields((PLARGE_INTEGER)&obi.CreationTime, (PTIME_FIELDS)&SystemTime);

        //Month starts from 0 index
        if (SystemTime.Month - 1 < 0) SystemTime.Month = 1;
        if (SystemTime.Month > 12) SystemTime.Month = 12;

        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        wsprintf(szBuffer, FORMATTED_TIME_DATE_VALUE,
            SystemTime.Hour,
            SystemTime.Minute,
            SystemTime.Second,
            SystemTime.Day,
            Months[SystemTime.Month - 1],
            SystemTime.Year);

        SetDlgItemText(hwndDlg, ID_OBJECT_SYMLINK_CREATION, szBuffer);
    }

    //
    // Query object basic and type info if needed.
    //
    if (ExtendedInfoAvailable == FALSE) {
        propSetDefaultInfo(Context, hwndDlg, hObject);
    }
    NtClose(hObject);
}

/*
* propBasicQueryKey
*
* Purpose:
*
* Set information values for Key object type
*
* If ExtendedInfoAvailable is FALSE then it calls propSetDefaultInfo to set Basic page properties
*
*/
VOID propBasicQueryKey(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg,
    _In_ BOOL ExtendedInfoAvailable
)
{
    NTSTATUS    status;
    ULONG       bytesNeeded;
    HANDLE      hObject;
    TIME_FIELDS	SystemTime;
    WCHAR       szBuffer[MAX_PATH];

    KEY_FULL_INFORMATION  kfi;

    SetDlgItemText(hwndDlg, ID_KEYSUBKEYS, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_KEYVALUES, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_KEYLASTWRITE, T_CannotQuery);

    if (Context == NULL) {
        return;
    }

    //
    // Open Key object.
    //
    hObject = NULL;
    if (!propOpenCurrentObject(Context, &hObject, KEY_QUERY_VALUE)) {
        return;
    }

    RtlSecureZeroMemory(&kfi, sizeof(KEY_FULL_INFORMATION));
    status = NtQueryKey(hObject, KeyFullInformation, &kfi,
        sizeof(KEY_FULL_INFORMATION), &bytesNeeded);

    if (NT_SUCCESS(status)) {

        //Subkeys count
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        ultostr(kfi.SubKeys, _strend(szBuffer));
        SetDlgItemText(hwndDlg, ID_KEYSUBKEYS, szBuffer);

        //Values count
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        ultostr(kfi.Values, _strend(szBuffer));
        SetDlgItemText(hwndDlg, ID_KEYVALUES, szBuffer);

        //LastWrite time
        RtlSecureZeroMemory(&SystemTime, sizeof(SystemTime));
        FileTimeToLocalFileTime((PFILETIME)&kfi.LastWriteTime,
            (PFILETIME)&kfi.LastWriteTime);
        RtlTimeToTimeFields((PLARGE_INTEGER)&kfi.LastWriteTime,
            (PTIME_FIELDS)&SystemTime);

        //Month starts from 0 index
        if (SystemTime.Month - 1 < 0) SystemTime.Month = 1;
        if (SystemTime.Month > 12) SystemTime.Month = 12;

        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        wsprintf(szBuffer, FORMATTED_TIME_DATE_VALUE,
            SystemTime.Hour,
            SystemTime.Minute,
            SystemTime.Second,
            SystemTime.Day,
            Months[SystemTime.Month - 1],
            SystemTime.Year);

        SetDlgItemText(hwndDlg, ID_KEYLASTWRITE, szBuffer);
    }

    //
    // Query object basic and type info if needed.
    //
    if (ExtendedInfoAvailable == FALSE) {
        propSetDefaultInfo(Context, hwndDlg, hObject);
    }
    NtClose(hObject);
}

/*
* propBasicQueryMutant
*
* Purpose:
*
* Set information values for Mutant object type
*
* If ExtendedInfoAvailable is FALSE then it calls propSetDefaultInfo to set Basic page properties
*
*/
VOID propBasicQueryMutant(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg,
    _In_ BOOL ExtendedInfoAvailable
)
{
    NTSTATUS status;
    ULONG    bytesNeeded;
    HANDLE   hObject;
    WCHAR    szBuffer[MAX_PATH];

    MUTANT_BASIC_INFORMATION mbi;

    SetDlgItemText(hwndDlg, ID_MUTANTABANDONED, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_MUTANTSTATE, T_CannotQuery);

    if (Context == NULL) {
        return;
    }

    //
    // Open Mutant object.
    //
    hObject = NULL;
    if (!propOpenCurrentObject(Context, &hObject, MUTANT_QUERY_STATE)) {
        return;
    }

    RtlSecureZeroMemory(&mbi, sizeof(MUTANT_BASIC_INFORMATION));

    status = NtQueryMutant(hObject, MutantBasicInformation, &mbi,
        sizeof(MUTANT_BASIC_INFORMATION), &bytesNeeded);
    if (NT_SUCCESS(status)) {

        //Abandoned
        SetDlgItemText(hwndDlg, ID_MUTANTABANDONED, (mbi.AbandonedState) ? TEXT("Yes") : TEXT("No"));

        //State
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, TEXT("Not Held"));
        if (mbi.OwnedByCaller) {
            wsprintf(szBuffer, TEXT("Held recursively %d times"), mbi.CurrentCount);
        }
        SetDlgItemText(hwndDlg, ID_MUTANTSTATE, szBuffer);
    }

    //
    // Query object basic and type info if needed.
    //
    if (ExtendedInfoAvailable == FALSE) {
        propSetDefaultInfo(Context, hwndDlg, hObject);
    }
    NtClose(hObject);
}

/*
* propBasicQuerySection
*
* Purpose:
*
* Set information values for Section object type
*
* If ExtendedInfoAvailable is FALSE then it calls propSetDefaultInfo to set Basic page properties
*
*/
VOID propBasicQuerySection(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg,
    _In_ BOOL ExtendedInfoAvailable
)
{
    BOOL      bSet;
    NTSTATUS  status;
    HANDLE    hObject;
    SIZE_T    bytesNeeded;
    LPWSTR    lpType;
    RECT      rGB;
    WCHAR     szBuffer[MAX_PATH * 2];

    SECTION_BASIC_INFORMATION sbi;
    SECTION_IMAGE_INFORMATION sii;

    SetDlgItemText(hwndDlg, ID_SECTION_ATTR, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_SECTIONSIZE, T_CannotQuery);

    if (Context == NULL) {
        return;
    }

    //
    // Open Section object.
    //
    hObject = NULL;
    if (!propOpenCurrentObject(Context, &hObject, SECTION_QUERY)) {
        return;
    }

    //this is for specific mars warning, mars doesn't recognize __stosb intrinsics
    szBuffer[0] = 0;

    //query basic information
    RtlSecureZeroMemory(&sbi, sizeof(SECTION_BASIC_INFORMATION));
    status = NtQuerySection(hObject, SectionBasicInformation, &sbi,
        sizeof(SECTION_BASIC_INFORMATION), &bytesNeeded);

    if (NT_SUCCESS(status)) {

        bSet = FALSE;
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        if (sbi.AllocationAttributes & SEC_BASED) {
            _strcat(szBuffer, TEXT("Based"));
            bSet = TRUE;
        }
        if (sbi.AllocationAttributes & SEC_NO_CHANGE) {
            if (bSet) _strcat(szBuffer, TEXT(" + "));
            _strcat(szBuffer, TEXT("NoChange"));
            bSet = TRUE;
        }
        if (sbi.AllocationAttributes & SEC_FILE) {
            if (bSet) _strcat(szBuffer, TEXT(" + "));
            _strcat(szBuffer, TEXT("File"));
            bSet = TRUE;
        }
        if (sbi.AllocationAttributes & SEC_IMAGE) {
            if (bSet) _strcat(szBuffer, TEXT(" + "));
            _strcat(szBuffer, TEXT("Image"));
            bSet = TRUE;
        }
        if (sbi.AllocationAttributes & SEC_RESERVE) {
            if (bSet) _strcat(szBuffer, TEXT(" + "));
            _strcat(szBuffer, TEXT("Reserve"));
            bSet = TRUE;
        }
        if (sbi.AllocationAttributes & SEC_COMMIT) {
            if (bSet) _strcat(szBuffer, TEXT(" + "));
            _strcat(szBuffer, TEXT("Commit"));
            bSet = TRUE;
        }
        if (sbi.AllocationAttributes & SEC_NOCACHE) {
            if (bSet) _strcat(szBuffer, TEXT(" + "));
            _strcat(szBuffer, TEXT("NoCache"));
            bSet = TRUE;
        }
        if (sbi.AllocationAttributes & SEC_GLOBAL) {
            if (bSet) _strcat(szBuffer, TEXT(" + "));
            _strcat(szBuffer, TEXT("Global"));
            bSet = TRUE;
        }
        if (sbi.AllocationAttributes & SEC_LARGE_PAGES) {
            if (bSet) _strcat(szBuffer, TEXT(" + "));
            _strcat(szBuffer, TEXT("LargePages"));
        }
        SetDlgItemText(hwndDlg, ID_SECTION_ATTR, szBuffer);

        //Size
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        wsprintf(szBuffer, TEXT("0x%I64X"), sbi.MaximumSize.QuadPart);
        SetDlgItemText(hwndDlg, ID_SECTIONSIZE, szBuffer);

        //query image information
        if ((sbi.AllocationAttributes & SEC_IMAGE) && (sbi.AllocationAttributes & SEC_FILE)) {

            RtlSecureZeroMemory(&sii, sizeof(SECTION_IMAGE_INFORMATION));
            status = NtQuerySection(hObject, SectionImageInformation, &sii,
                sizeof(SECTION_IMAGE_INFORMATION), &bytesNeeded);

            if (NT_SUCCESS(status)) {

                //show hidden controls
                if (GetWindowRect(GetDlgItem(hwndDlg, ID_IMAGEINFO), &rGB)) {
                    EnumChildWindows(hwndDlg, supEnumEnableChildWindows, (LPARAM)&rGB);
                }

                //Entry			
                RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
                wsprintf(szBuffer, TEXT("0x%I64X"), (ULONG_PTR)sii.TransferAddress);
                SetDlgItemText(hwndDlg, ID_IMAGE_ENTRY, szBuffer);

                //Stack Reserve
                RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
                wsprintf(szBuffer, TEXT("0x%I64X"), sii.MaximumStackSize);
                SetDlgItemText(hwndDlg, ID_IMAGE_STACKRESERVE, szBuffer);

                //Stack Commit
                RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
                wsprintf(szBuffer, TEXT("0x%I64X"), sii.CommittedStackSize);
                SetDlgItemText(hwndDlg, ID_IMAGE_STACKCOMMIT, szBuffer);

                //Executable			
                SetDlgItemText(hwndDlg, ID_IMAGE_EXECUTABLE,
                    (sii.ImageContainsCode) ? TEXT("Yes") : TEXT("No"));

                //Subsystem
                lpType = TEXT("Unknown");
                switch (sii.SubSystemType) {
                case IMAGE_SUBSYSTEM_NATIVE:
                    lpType = TEXT("Native");
                    break;
                case IMAGE_SUBSYSTEM_WINDOWS_GUI:
                    lpType = TEXT("Windows GUI");
                    break;
                case IMAGE_SUBSYSTEM_WINDOWS_CUI:
                    lpType = TEXT("Windows Console");
                    break;
                case IMAGE_SUBSYSTEM_OS2_CUI:
                    lpType = TEXT("OS/2 Console");
                    break;
                case IMAGE_SUBSYSTEM_POSIX_CUI:
                    lpType = TEXT("Posix Console");
                    break;
                case IMAGE_SUBSYSTEM_XBOX:
                    lpType = TEXT("XBox");
                    break;
                case IMAGE_SUBSYSTEM_EFI_APPLICATION:
                    lpType = TEXT("EFI Application");
                    break;
                case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
                    lpType = TEXT("EFI Boot Service Driver");
                    break;
                case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
                    lpType = TEXT("EFI Runtime Driver");
                    break;
                case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
                    lpType = TEXT("Windows Boot Application");
                    break;
                }
                SetDlgItemText(hwndDlg, ID_IMAGE_SUBSYSTEM, lpType);

                //Major Version
                RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
                ultostr(sii.SubSystemMajorVersion, _strend(szBuffer));
                SetDlgItemText(hwndDlg, ID_IMAGE_MJV, szBuffer);

                //Minor Version
                RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
                ultostr(sii.SubSystemMinorVersion, _strend(szBuffer));
                SetDlgItemText(hwndDlg, ID_IMAGE_MNV, szBuffer);
            }
        }
    }

    //
    // Query object basic and type info if needed.
    //
    if (ExtendedInfoAvailable == FALSE) {
        propSetDefaultInfo(Context, hwndDlg, hObject);
    }
    NtClose(hObject);
}

/*
* propBasicQueryWindowStation
*
* Purpose:
*
* Set information values for WindowStation object type (managed by win32k services)
*
* If ExtendedInfoAvailable is FALSE then it calls propSetDefaultInfo to set Basic page properties
*
*/
VOID propBasicQueryWindowStation(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg,
    _In_ BOOL ExtendedInfoAvailable
)
{
    DWORD           bytesNeeded;
    HWINSTA         hObject;
    USEROBJECTFLAGS userFlags;

    SetDlgItemText(hwndDlg, ID_WINSTATIONVISIBLE, T_CannotQuery);

    if (Context == NULL) {
        return;
    }

    //
    // Open Winstation object.
    //
    hObject = NULL;
    if (!propOpenCurrentObject(Context, &hObject, WINSTA_READATTRIBUTES)) {
        return;
    }

    RtlSecureZeroMemory(&userFlags, sizeof(userFlags));
    if (GetUserObjectInformation(hObject, UOI_FLAGS, &userFlags,
        sizeof(USEROBJECTFLAGS), &bytesNeeded))
    {
        SetDlgItemText(hwndDlg, ID_WINSTATIONVISIBLE,
            (userFlags.dwFlags & WSF_VISIBLE) ? TEXT("Yes") : TEXT("No"));
    }

    //
    // Query object basic and type info if needed.
    //
    if (ExtendedInfoAvailable == FALSE) {
        propSetDefaultInfo(Context, hwndDlg, hObject);
    }
    CloseWindowStation(hObject);
}

/*
* propBasicQueryDriver
*
* Purpose:
*
* Set information values for Driver object type
*
* Viewing \Drivers subdirectory requires full access token
*
*/
VOID propBasicQueryDriver(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    RECT    rGB;
    LPWSTR  lpItemText;

    if (Context == NULL) {
        return;
    }

    //
    // For performance reasons instead of query again
    // we use description from main object list.
    //
    lpItemText = Context->lpDescription;
    if (lpItemText) {
        //show hidden controls
        if (GetWindowRect(GetDlgItem(hwndDlg, ID_DRIVERINFO), &rGB)) {
            EnumChildWindows(hwndDlg, supEnumEnableChildWindows, (LPARAM)&rGB);
        }
        SetDlgItemText(hwndDlg, ID_DRIVERDISPLAYNAME, lpItemText);
    }
}

/*
* propBasicQueryDevice
*
* Purpose:
*
* Set information values for Device object type
*
*/
VOID propBasicQueryDevice(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    RECT    rGB;
    LPWSTR  lpItemText;

    if (Context == NULL) {
        return;
    }

    //
    // For performance reasons instead of query again
    // we use description from main object list.
    //
    lpItemText = Context->lpDescription;
    if (lpItemText) {
        //show hidden controls
        if (GetWindowRect(GetDlgItem(hwndDlg, ID_DEVICEINFO), &rGB)) {
            EnumChildWindows(hwndDlg, supEnumEnableChildWindows, (LPARAM)&rGB);
        }
        SetDlgItemText(hwndDlg, ID_DEVICEDESCRIPTION, lpItemText);
    }
}

/*
* propBasicQueryMemoryPartition
*
* Purpose:
*
* Set information values for Partition object type
*
* If ExtendedInfoAvailable is FALSE then it calls propSetDefaultInfo to set Basic page properties
*
*/
VOID propBasicQueryMemoryPartition(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    HANDLE hObject;

    if (Context == NULL) {
        return;
    }

    //
    // Open Memory Partition object.
    //
    hObject = NULL;
    if (!propOpenCurrentObject(Context, &hObject, MEMORY_PARTITION_QUERY_ACCESS))
        return;

    //TODO more info here
    //FIXME FIXME


    //
    // Query object basic and type info if needed.
    //
    propSetDefaultInfo(Context, hwndDlg, hObject);
    NtClose(hObject);
}

/*
* propBasicQueryJob
*
* Purpose:
*
* Set information values for Job object type
*
* If ExtendedInfoAvailable is FALSE then it calls propSetDefaultInfo to set Basic page properties
*
*/
VOID propBasicQueryJob(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg,
    _In_ BOOL ExtendedInfoAvailable
)
{
    BOOL        cond = FALSE;
    DWORD       i;
    HWND        hwndCB;
    HANDLE      hObject;
    NTSTATUS    status;
    ULONG       bytesNeeded;
    ULONG_PTR   ProcessId;
    PVOID       ProcessList;
    WCHAR       szProcessName[MAX_PATH + 1];
    WCHAR       szBuffer[MAX_PATH * 2];
    TIME_FIELDS SystemTime;

    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION jbai;
    PJOBOBJECT_BASIC_PROCESS_ID_LIST       pJobProcList;

    SetDlgItemText(hwndDlg, ID_JOBTOTALPROCS, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_JOBACTIVEPROCS, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_JOBTERMINATEDPROCS, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_JOBTOTALUMTIME, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_JOBTOTALKMTIME, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_JOBTOTALPF, T_CannotQuery);

    if (Context == NULL) {
        return;
    }

    //
    // Open Job object.
    //
    hObject = NULL;
    if (!propOpenCurrentObject(Context, &hObject, JOB_OBJECT_QUERY)) {
        return;
    }

    //query basic information
    RtlSecureZeroMemory(&jbai, sizeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
    status = NtQueryInformationJobObject(hObject, JobObjectBasicAccountingInformation,
        &jbai, sizeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION), &bytesNeeded);
    if (NT_SUCCESS(status)) {

        //Total processes
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        ultostr(jbai.TotalProcesses, szBuffer);
        SetDlgItemText(hwndDlg, ID_JOBTOTALPROCS, szBuffer);

        //Active processes
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        ultostr(jbai.ActiveProcesses, szBuffer);
        SetDlgItemText(hwndDlg, ID_JOBACTIVEPROCS, szBuffer);

        //Terminated processes
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        ultostr(jbai.TotalTerminatedProcesses, szBuffer);
        SetDlgItemText(hwndDlg, ID_JOBTERMINATEDPROCS, szBuffer);

        //Total user time
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        RtlSecureZeroMemory(&SystemTime, sizeof(SystemTime));
        RtlTimeToTimeFields(&jbai.TotalUserTime, &SystemTime);
        wsprintf(szBuffer, FORMATTED_TIME_VALUE_MS,
            SystemTime.Hour,
            SystemTime.Minute,
            SystemTime.Second,
            SystemTime.Milliseconds);
        SetDlgItemText(hwndDlg, ID_JOBTOTALUMTIME, szBuffer);

        //Total kernel time
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        RtlTimeToTimeFields(&jbai.TotalKernelTime, &SystemTime);
        wsprintf(szBuffer, FORMATTED_TIME_VALUE_MS,
            SystemTime.Hour,
            SystemTime.Minute,
            SystemTime.Second,
            SystemTime.Milliseconds);
        SetDlgItemText(hwndDlg, ID_JOBTOTALKMTIME, szBuffer);

        //Page faults
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        ultostr(jbai.TotalPageFaultCount, szBuffer);
        SetDlgItemText(hwndDlg, ID_JOBTOTALPF, szBuffer);

        //Job process list
        pJobProcList = NULL;
        do {

            hwndCB = GetDlgItem(hwndDlg, IDC_JOB_PLIST);
            if (hwndCB == NULL)
                break;

            //allocate default size
            bytesNeeded = sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST);
            pJobProcList = supVirtualAlloc(bytesNeeded);
            if (pJobProcList == NULL)
                break;

            //if buffer is not enough, reallocate it
            status = NtQueryInformationJobObject(hObject,
                JobObjectBasicProcessIdList,
                pJobProcList,
                bytesNeeded,
                &bytesNeeded);

            if (status == STATUS_BUFFER_TOO_SMALL) {

                supVirtualFree(pJobProcList);
                pJobProcList = supVirtualAlloc(bytesNeeded);
                if (pJobProcList == NULL)
                    break;

                status = NtQueryInformationJobObject(hObject,
                    JobObjectBasicProcessIdList,
                    pJobProcList,
                    bytesNeeded,
                    &bytesNeeded);

                if (!NT_SUCCESS(status))
                    break;
            }
            EnableWindow(hwndCB, (pJobProcList->NumberOfProcessIdsInList > 0) ? TRUE : FALSE);
            SendMessage(hwndCB, CB_RESETCONTENT, (WPARAM)0, (LPARAM)0);

            // 
            // If any present then output processes in the list.
            //
            if (pJobProcList->NumberOfProcessIdsInList > 0) {
                ProcessList = supGetSystemInfo(SystemProcessInformation);
                if (ProcessList) {
                    for (i = 0; i < pJobProcList->NumberOfProcessIdsInList; i++) {
                        ProcessId = pJobProcList->ProcessIdList[i];
                        RtlSecureZeroMemory(&szProcessName, sizeof(szProcessName));

                        //
                        // Query process name.
                        //
                        if (!supQueryProcessName(ProcessId, ProcessList, szProcessName, MAX_PATH)) {
                            _strcpy(szProcessName, TEXT("UnknownProcess"));
                        }

                        wsprintf(szBuffer, TEXT("[0x%I64X:%I64u] %ws"), ProcessId, ProcessId, szProcessName);
                        SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
                    }
                    SendMessage(hwndCB, CB_SETCURSEL, (WPARAM)0, (LPARAM)0);
                    supHeapFree(ProcessList);
                }
            }
        } while (cond);

        if (pJobProcList != NULL) {
            supVirtualFree(pJobProcList);
        }
    }

    //
    // Query object basic and type info if needed.
    //
    if (ExtendedInfoAvailable == FALSE) {
        propSetDefaultInfo(Context, hwndDlg, hObject);
    }
    NtClose(hObject);
}

/*
* propSetBasicInfoEx
*
* Purpose:
*
* Set information values received with kldbgdrv help
*
*/
VOID propSetBasicInfoEx(
    _In_ HWND hwndDlg,
    _In_ POBJINFO InfoObject
)
{
    INT     i;
    HWND    hwndCB;
    WCHAR   szBuffer[MAX_PATH];

    if (InfoObject == NULL)
        return;

    //Object Address
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    szBuffer[0] = L'0';
    szBuffer[1] = L'x';
    u64tohex(InfoObject->ObjectAddress, &szBuffer[2]);
    SetDlgItemText(hwndDlg, ID_OBJECT_ADDR, szBuffer);

    //Header Address
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    szBuffer[0] = L'0';
    szBuffer[1] = L'x';
    u64tohex(InfoObject->HeaderAddress, &szBuffer[2]);
    SetDlgItemText(hwndDlg, ID_OBJECT_HEADER, szBuffer);

    //Reference Count
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    ultostr(InfoObject->ObjectHeader.PointerCount, _strend(szBuffer));
    SetDlgItemText(hwndDlg, ID_OBJECT_REFC, szBuffer);

    //Handle Count
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    ultostr(InfoObject->ObjectHeader.HandleCount, _strend(szBuffer));
    SetDlgItemText(hwndDlg, ID_OBJECT_HANDLES, szBuffer);

    //NonPagedPoolCharge
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    ultostr(InfoObject->ObjectQuotaHeader.NonPagedPoolCharge, szBuffer);
    SetDlgItemText(hwndDlg, ID_OBJECT_NP_CHARGE, szBuffer);

    //PagedPoolCharge
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    ultostr(InfoObject->ObjectQuotaHeader.PagedPoolCharge, _strend(szBuffer));
    SetDlgItemText(hwndDlg, ID_OBJECT_PP_CHARGE, szBuffer);

    //Attributes
    hwndCB = GetDlgItem(hwndDlg, IDC_OBJECT_FLAGS);
    if (hwndCB) {
        EnableWindow(hwndCB, (InfoObject->ObjectHeader.Flags > 0) ? TRUE : FALSE);
        SendMessage(hwndCB, CB_RESETCONTENT, (WPARAM)0, (LPARAM)0);
        if (InfoObject->ObjectHeader.Flags > 0) {
            for (i = 0; i < 8; i++) {

                if (GET_BIT(InfoObject->ObjectHeader.Flags, i))

                    SendMessage(hwndCB,
                        CB_ADDSTRING,
                        (WPARAM)0,
                        (LPARAM)T_ObjectFlags[i]);
            }
            SendMessage(hwndCB, CB_SETCURSEL, (WPARAM)0, (LPARAM)0);
        }
    }
}

/*
* propBasicQueryDesktop
*
* Purpose:
*
* Set information values for Desktop object type
*
* Support is very limited because of win32k type origin.
*
*/
VOID propBasicQueryDesktop(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    BOOL        bExtendedInfoAvailable;
    HANDLE      hDesktop;
    ULONG_PTR   ObjectAddress, HeaderAddress, InfoHeaderAddress;
    WCHAR       szBuffer[MAX_PATH + 1];
    OBJINFO     InfoObject;

    if (Context == NULL) {
        return;
    }

    //
    // Open Desktop object.
    //
    // Restriction: 
    // This will open only current winsta desktops
    //
    hDesktop = NULL;
    if (!propOpenCurrentObject(Context, &hDesktop, DESKTOP_READOBJECTS)) {
        return;
    }

    bExtendedInfoAvailable = FALSE;
    ObjectAddress = 0;
    if (supQueryObjectFromHandle(hDesktop, &ObjectAddress, NULL)) {
        HeaderAddress = (ULONG_PTR)OBJECT_TO_OBJECT_HEADER(ObjectAddress);

        //we can use driver
        if (g_kdctx.hDevice != NULL) {
            RtlSecureZeroMemory(&InfoObject, sizeof(InfoObject));
            InfoObject.HeaderAddress = HeaderAddress;
            InfoObject.ObjectAddress = ObjectAddress;
            //dump object header
            bExtendedInfoAvailable = kdReadSystemMemory(HeaderAddress,
                &InfoObject.ObjectHeader, sizeof(OBJECT_HEADER));
            if (bExtendedInfoAvailable) {
                //dump quota info
                InfoHeaderAddress = 0;
                if (ObHeaderToNameInfoAddress(InfoObject.ObjectHeader.InfoMask,
                    HeaderAddress, &InfoHeaderAddress, HeaderQuotaInfoFlag))
                {
                    kdReadSystemMemory(InfoHeaderAddress,
                        &InfoObject.ObjectQuotaHeader, sizeof(OBJECT_HEADER_QUOTA_INFO));
                }
                propSetBasicInfoEx(hwndDlg, &InfoObject);
            }
        }
        //cannot query extended info, output what we have
        if (bExtendedInfoAvailable == FALSE) {
            //Object Address
            RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
            szBuffer[0] = L'0';
            szBuffer[1] = L'x';
            u64tohex(ObjectAddress, &szBuffer[2]);
            SetDlgItemText(hwndDlg, ID_OBJECT_ADDR, szBuffer);

            //Object Address
            RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
            szBuffer[0] = L'0';
            szBuffer[1] = L'x';
            u64tohex(HeaderAddress, &szBuffer[2]);
            SetDlgItemText(hwndDlg, ID_OBJECT_HEADER, szBuffer);
        }
    }

    //
    // Query object basic and type info if needed.
    //
    if (bExtendedInfoAvailable == FALSE) {
        propSetDefaultInfo(Context, hwndDlg, hDesktop);
    }
    CloseDesktop(hDesktop);
}

/*
* propSetBasicInfo
*
* Purpose:
*
* Set information values for Basic properties page
*
*/
VOID propSetBasicInfo(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    BOOL     ExtendedInfoAvailable = FALSE;
    POBJINFO InfoObject = NULL;

    if (Context == NULL) {
        return;
    }
    SetDlgItemText(hwndDlg, ID_OBJECT_NAME, Context->lpObjectName);
    SetDlgItemText(hwndDlg, ID_OBJECT_TYPE, Context->lpObjectType);

    //desktops should be parsed differently
    if (Context->TypeIndex != TYPE_DESKTOP) {

        //try to dump object info
        InfoObject = ObQueryObject(Context->lpCurrentObjectPath, Context->lpObjectName);
        ExtendedInfoAvailable = (InfoObject != NULL);
        if (InfoObject == NULL) {
            SetDlgItemText(hwndDlg, ID_OBJECT_ADDR, L"");
            SetDlgItemText(hwndDlg, ID_OBJECT_HEADER, L"");
        }
        else {
            //make copy of received dump
            supCopyMemory(&Context->ObjectInfo, sizeof(OBJINFO), InfoObject, sizeof(OBJINFO));

            //
            // Set Object Address, Header Address, NP/PP Charge, RefCount, HandleCount, Attributes.
            //
            propSetBasicInfoEx(hwndDlg, InfoObject);
            supHeapFree(InfoObject);
        }
    }

    //
    // Query Basic Information extended fields per Type.
    // If extended info not available each routine should query basic info itself.
    //
    switch (Context->TypeIndex) {
    case TYPE_DIRECTORY:
        //if TRUE skip this because directory is basic dialog and basic info already set
        if (ExtendedInfoAvailable == FALSE) {
            propBasicQueryDirectory(Context, hwndDlg);
        }
        break;
    case TYPE_DRIVER:
        propBasicQueryDriver(Context, hwndDlg);
        break;
    case TYPE_DEVICE:
        propBasicQueryDevice(Context, hwndDlg);
        break;
    case TYPE_SYMLINK:
        propBasicQuerySymlink(Context, hwndDlg, ExtendedInfoAvailable);
        break;
    case TYPE_KEY:
        propBasicQueryKey(Context, hwndDlg, ExtendedInfoAvailable);
        break;
    case TYPE_MUTANT:
        propBasicQueryMutant(Context, hwndDlg, ExtendedInfoAvailable);
        break;
    case TYPE_EVENT:
        propBasicQueryEvent(Context, hwndDlg, ExtendedInfoAvailable);
        break;
    case TYPE_TIMER:
        propBasicQueryTimer(Context, hwndDlg, ExtendedInfoAvailable);
        break;
    case TYPE_SEMAPHORE:
        propBasicQuerySemaphore(Context, hwndDlg, ExtendedInfoAvailable);
        break;
    case TYPE_SECTION:
        propBasicQuerySection(Context, hwndDlg, ExtendedInfoAvailable);
        break;
    case TYPE_WINSTATION:
        propBasicQueryWindowStation(Context, hwndDlg, ExtendedInfoAvailable);
        break;
    case TYPE_JOB:
        propBasicQueryJob(Context, hwndDlg, ExtendedInfoAvailable);
        break;
    case TYPE_DESKTOP:
        propBasicQueryDesktop(Context, hwndDlg);
        break;
    case TYPE_IOCOMPLETION:
        propBasicQueryIoCompletion(Context, hwndDlg, ExtendedInfoAvailable);
        break;
    case TYPE_MEMORYPARTITION:
        propBasicQueryMemoryPartition(Context, hwndDlg);
        break;
    }

}

/*
* BasicPropDialogProc
*
* Purpose:
*
* Basic Properties Dialog Procedure
*
* WM_SHOWWINDOW - when wParam is TRUE it sets "Basic" page object information.
* WM_INITDIALOG - set context window prop.
* WM_DESTROY - remove context window prop.
*
*/
INT_PTR CALLBACK BasicPropDialogProc(
    _In_  HWND hwndDlg,
    _In_  UINT uMsg,
    _In_  WPARAM wParam,
    _In_  LPARAM lParam
)
{
    HDC               hDc;
    PAINTSTRUCT       Paint;
    PROPSHEETPAGE    *pSheet = NULL;
    PROP_OBJECT_INFO *Context = NULL;

    switch (uMsg) {

    case WM_INITDIALOG:
        pSheet = (PROPSHEETPAGE *)lParam;
        if (pSheet) {
            SetProp(hwndDlg, T_PROPCONTEXT, (HANDLE)pSheet->lParam);
        }
        return 1;
        break;

    case WM_SHOWWINDOW:
        if (wParam) {
            Context = GetProp(hwndDlg, T_PROPCONTEXT);
            if (Context) {
                propSetBasicInfo(Context, hwndDlg);
            }
        }
        return 1;
        break;

    case WM_PAINT:

        Context = GetProp(hwndDlg, T_PROPCONTEXT);
        if (Context) {
            hDc = BeginPaint(hwndDlg, &Paint);
            if (hDc) {
                ImageList_Draw(g_ListViewImages, Context->TypeIndex, hDc, 24, 34, ILD_NORMAL | ILD_TRANSPARENT);
                EndPaint(hwndDlg, &Paint);
            }
        }
        return 1;
        break;

    case WM_DESTROY:
        RemoveProp(hwndDlg, T_PROPCONTEXT);
        break;

    }
    return 0;
}
