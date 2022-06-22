/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2022
*
*  TITLE:       PROPDRIVER.C
*
*  VERSION:     2.00
*
*  DATE:        19 Jun 2022
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "props.h"

#define REGEDITWNDCLASS           L"RegEdit_RegEdit"
#define REGEDIT_EXE               L"regedit.exe"
#define SHELL_OPEN_VERB           L"open"

//
// Path to navigate in the regedit window treeview.
//
#define PROPDRVREGSERVICESKEY     L"\\HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\"
#define PROPDRVREGSERVICESKEYLEN  sizeof(PROPDRVREGSERVICESKEY) - sizeof(WCHAR)


/*
* DriverShowChildWindows
*
* Purpose:
*
* Makes window controls visible/invisible
*
*/
BOOL WINAPI DriverShowChildWindows(
    _In_ HWND hwnd,
    _In_ LPARAM lParam
)
{
    ShowWindow(hwnd, (INT)lParam);
    return TRUE;
}

/*
* DriverSetInfo
*
* Purpose:
*
* Sets registry info for selected driver object
*
*/
VOID DriverSetInfo(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    BOOL                    bResult = FALSE, fGroup, bRet;
    INT                     nEndOfList, nEnd, nStart;
    DWORD                   i, bytesNeeded, dwServices, dwGroups;
    LPWSTR                  lpType;
    SC_HANDLE               SchSCManager = NULL, schService = NULL;
    LPENUM_SERVICE_STATUS   lpDependencies = NULL;
    LPQUERY_SERVICE_CONFIG  psci = NULL;
    LPSERVICE_DESCRIPTION   psd;
    SERVICE_STATUS_PROCESS  ssp;
    ENUM_SERVICE_STATUS     ess;
    WCHAR                   szBuffer[MAX_PATH + 1];

    __try {

        ShowWindow(GetDlgItem(hwndDlg, IDC_QUERYFAIL), FALSE);

        do {
            SchSCManager = OpenSCManager(
                NULL,
                NULL,
                SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);

            if (SchSCManager == NULL)
                break;

            schService = OpenService(
                SchSCManager,
                Context->NtObjectName.Buffer,
                SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS);

            if (schService == NULL)
                break;

            bytesNeeded = 0;
            bResult = QueryServiceConfig(
                schService,
                NULL,
                0,
                &bytesNeeded);

            if ((bResult == FALSE) && (bytesNeeded == 0))
                break;

            psci = (LPQUERY_SERVICE_CONFIG)supHeapAlloc(bytesNeeded);
            if (psci == NULL)
                break;

            //disable comboboxes
            EnableWindow(GetDlgItem(hwndDlg, IDC_SERVICE_DEPENDENTSERVICES), FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_SERVICE_DEPENDSONSERVICE), FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_SERVICE_DEPENDSONGROUP), FALSE);

            bResult = QueryServiceConfig(schService, psci, bytesNeeded, &bytesNeeded);
            if (bResult) {
                //set key name (identical to object name)
                SetDlgItemText(hwndDlg, IDC_SERVICE_KEYNAME, Context->NtObjectName.Buffer);
                //set image path info
                SetDlgItemText(hwndDlg, IDC_SERVICE_IMAGEPATH, psci->lpBinaryPathName);
                //set display name
                SetDlgItemText(hwndDlg, IDC_SERVICE_DISPLAYNAME, psci->lpDisplayName);
                //set load order group
                SetDlgItemText(hwndDlg, IDC_SERVICE_LOADORDERGROUP, psci->lpLoadOrderGroup);

                //Service Type
                lpType = T_UnknownType;
                switch (psci->dwServiceType) {
                case SERVICE_KERNEL_DRIVER:
                    lpType = TEXT("Kernel-Mode Driver");
                    break;
                case SERVICE_FILE_SYSTEM_DRIVER:
                    lpType = TEXT("File System Driver");
                    break;
                case SERVICE_ADAPTER:
                    lpType = TEXT("Adapter");
                    break;
                case SERVICE_RECOGNIZER_DRIVER:
                    lpType = TEXT("File System Recognizer");
                    break;
                case SERVICE_WIN32_OWN_PROCESS:
                    lpType = TEXT("Own Process");
                    break;
                case SERVICE_WIN32_SHARE_PROCESS:
                    lpType = TEXT("Share Process");
                    break;
                case (SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS):
                    lpType = TEXT("Own Process (Interactive)");
                    SetDlgItemText(hwndDlg, ID_SERVICE_NAME, psci->lpServiceStartName);
                    break;
                case (SERVICE_WIN32_SHARE_PROCESS | SERVICE_INTERACTIVE_PROCESS):
                    lpType = TEXT("Share Process (Interactive)");
                    SetDlgItemText(hwndDlg, ID_SERVICE_NAME, psci->lpServiceStartName);
                    break;
                case SERVICE_PKG_SERVICE:
                    lpType = TEXT("Package");
                    break;
                }
                SetDlgItemText(hwndDlg, ID_SERVICE_TYPE, lpType);

                //Start Type
                lpType = T_UnknownType;
                switch (psci->dwStartType) {
                case SERVICE_BOOT_START:
                    lpType = TEXT("Boot");
                    break;
                case SERVICE_SYSTEM_START:
                    lpType = TEXT("System");
                    break;
                case SERVICE_AUTO_START:
                    lpType = TEXT("Auto");
                    break;
                case SERVICE_DEMAND_START:
                    lpType = TEXT("On Demand");
                    break;
                case SERVICE_DISABLED:
                    lpType = TEXT("Disabled");
                    break;
                }
                SetDlgItemText(hwndDlg, ID_SERVICE_START, lpType);

                //Error Control
                lpType = T_Unknown;
                switch (psci->dwErrorControl) {
                case SERVICE_ERROR_IGNORE:
                    lpType = TEXT("Ignore");
                    break;
                case SERVICE_ERROR_NORMAL:
                    lpType = TEXT("Normal");
                    break;
                case SERVICE_ERROR_SEVERE:
                    lpType = TEXT("Severe");
                    break;
                case SERVICE_ERROR_CRITICAL:
                    lpType = TEXT("Critical");
                    break;
                }
                SetDlgItemText(hwndDlg, ID_SERVICE_ERROR, lpType);

                //dwTagId
                if (psci->dwTagId) {
                    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
                    ultostr(psci->dwTagId, szBuffer);
                    SetDlgItemText(hwndDlg, ID_SERVICE_TAG, szBuffer);
                }
                else {
                    //not assigned tag
                    SetDlgItemText(hwndDlg, ID_SERVICE_TAG, T_NotAssigned);
                }

                //State
                RtlSecureZeroMemory(&ssp, sizeof(ssp));
                if (QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO,
                    (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded))
                {
                    lpType = T_Unknown;
                    switch (ssp.dwCurrentState) {
                    case SERVICE_STOPPED:
                        lpType = TEXT("Stopped");
                        break;
                    case SERVICE_START_PENDING:
                        lpType = TEXT("Start Pending");
                        break;
                    case SERVICE_STOP_PENDING:
                        lpType = TEXT("Stop Pending");
                        break;
                    case SERVICE_RUNNING:
                        lpType = TEXT("Running");
                        break;
                    case SERVICE_CONTINUE_PENDING:
                        lpType = TEXT("Continue Pending");
                        break;
                    case SERVICE_PAUSE_PENDING:
                        lpType = TEXT("Pause Pending");
                        break;
                    case SERVICE_PAUSED:
                        lpType = TEXT("Paused");
                        break;
                    }
                    SetDlgItemText(hwndDlg, ID_SERVICE_CURRENT, lpType);
                }
                else {
                    SetDlgItemText(hwndDlg, ID_SERVICE_CURRENT, T_CannotQuery);
                }

                //Service Description
                bRet = FALSE;
                SetDlgItemText(hwndDlg, ID_SERVICE_DESCRIPTION, T_EmptyString);
                bytesNeeded = 0x1000;
                psd = (LPSERVICE_DESCRIPTION)supHeapAlloc(bytesNeeded);
                if (psd) {

                    bRet = QueryServiceConfig2(
                        schService,
                        SERVICE_CONFIG_DESCRIPTION,
                        (LPBYTE)psd,
                        bytesNeeded,
                        &bytesNeeded);

                    if ((bRet == FALSE) && (bytesNeeded != 0)) {
                        supHeapFree(psd);
                        psd = (LPSERVICE_DESCRIPTION)supHeapAlloc(bytesNeeded);
                    }
                    if (psd) {
                        //set description or hide window
                        bRet = QueryServiceConfig2(
                            schService,
                            SERVICE_CONFIG_DESCRIPTION,
                            (LPBYTE)psd,
                            bytesNeeded,
                            &bytesNeeded);

                        if (bRet) {
                            SetDlgItemText(hwndDlg, IDC_SERVICE_DESCRIPTION, psd->lpDescription);
                        }
                        supHeapFree(psd);
                    }
                }
                if (bRet == FALSE) {
                    //not enough memory, hide description window
                    ShowWindow(GetDlgItem(hwndDlg, IDC_SERVICE_DESCRIPTION), SW_HIDE);
                }


                //Service Dependencies
                if (psci->lpDependencies) {

                    //first list DependsOnService, DependsOnGroup

                    nEndOfList = 0;
                    nEnd = 0;
                    nStart = 0;
                    dwGroups = 0;
                    dwServices = 0;

                    //calc total number of symbols
                    while ((psci->lpDependencies[nEndOfList] != L'\0') || (psci->lpDependencies[nEndOfList + 1] != L'\0'))
                        nEndOfList++;

                    if (nEndOfList > 0) {

                        SendDlgItemMessage(hwndDlg, IDC_SERVICE_DEPENDSONGROUP, CB_RESETCONTENT, (WPARAM)0, (LPARAM)0);
                        SendDlgItemMessage(hwndDlg, IDC_SERVICE_DEPENDSONSERVICE, CB_RESETCONTENT, (WPARAM)0, (LPARAM)0);

                        //iterate through MULTI_SZ string
                        do {
                            while (psci->lpDependencies[nEnd] != TEXT('\0')) {
                                nEnd++;
                            }

                            RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
                            //maximum bytes that can be copied is sizeof(szBuffer)
                            _strncpy(szBuffer, sizeof(szBuffer), &psci->lpDependencies[nStart], nEnd);

                            //check if dependency is a group (has "+" before name)
                            fGroup = (szBuffer[0] == SC_GROUP_IDENTIFIER);
                            if (fGroup) {
                                SendDlgItemMessage(hwndDlg, IDC_SERVICE_DEPENDSONGROUP, CB_ADDSTRING,
                                    (WPARAM)0, (LPARAM)&szBuffer[1]);
                                dwGroups++;
                            }
                            else {
                                SendDlgItemMessage(hwndDlg, IDC_SERVICE_DEPENDSONSERVICE, CB_ADDSTRING,
                                    (WPARAM)0, (LPARAM)&szBuffer);
                                dwServices++;
                            }
                            nEnd++;
                            nStart = nEnd;
                        } while (nEnd < nEndOfList);

                        //group present, enable combobox
                        if (dwGroups > 0) {
                            EnableWindow(GetDlgItem(hwndDlg, IDC_SERVICE_DEPENDSONGROUP), TRUE);
                            SendDlgItemMessage(hwndDlg, IDC_SERVICE_DEPENDSONGROUP, CB_SETCURSEL,
                                (WPARAM)0, (LPARAM)0);
                        }
                        //service present, enable combobox
                        if (dwServices > 0) {
                            EnableWindow(GetDlgItem(hwndDlg, IDC_SERVICE_DEPENDSONSERVICE), TRUE);
                            SendDlgItemMessage(hwndDlg, IDC_SERVICE_DEPENDSONSERVICE, CB_SETCURSEL,
                                (WPARAM)0, (LPARAM)0);
                        }
                    } //if (nEndOfList > 0)

                    //second list services that depends on this service
                    SendDlgItemMessage(hwndDlg, IDC_SERVICE_DEPENDENTSERVICES, CB_RESETCONTENT,
                        (WPARAM)0, (LPARAM)0);

                    dwServices = 0;
                    bytesNeeded = 1024;
                    bRet = FALSE;

                    //avoid SCM unexpected behaviour by using preallocated buffer
                    lpDependencies = (LPENUM_SERVICE_STATUS)supHeapAlloc(bytesNeeded);
                    if (lpDependencies) {

                        bRet = EnumDependentServices(
                            schService,
                            SERVICE_STATE_ALL,
                            lpDependencies,
                            bytesNeeded,
                            &bytesNeeded,
                            &dwServices);

                        if (bRet && (GetLastError() == ERROR_MORE_DATA)) {
                            //more memory needed for enum
                            supHeapFree(lpDependencies);
                            dwServices = 0;
                            lpDependencies = (LPENUM_SERVICE_STATUS)supHeapAlloc((SIZE_T)bytesNeeded);
                            if (lpDependencies) {

                                bRet = EnumDependentServices(
                                    schService,
                                    SERVICE_STATE_ALL,
                                    lpDependencies,
                                    bytesNeeded,
                                    &bytesNeeded,
                                    &dwServices);

                            }
                        }

                        if (lpDependencies) {
                            //list dependents
                            if (bRet && dwServices) {
                                for (i = 0; i < dwServices; i++) {
                                    ess = *(lpDependencies + i);

                                    SendDlgItemMessage(
                                        hwndDlg,
                                        IDC_SERVICE_DEPENDENTSERVICES,
                                        CB_ADDSTRING,
                                        (WPARAM)0,
                                        (LPARAM)ess.lpServiceName);
                                }
                                //enable combobox and set current selection to the first item
                                EnableWindow(GetDlgItem(hwndDlg, IDC_SERVICE_DEPENDENTSERVICES), TRUE);

                                SendDlgItemMessage(
                                    hwndDlg,
                                    IDC_SERVICE_DEPENDENTSERVICES,
                                    CB_SETCURSEL,
                                    (WPARAM)0,
                                    (LPARAM)0);
                            }
                            supHeapFree(lpDependencies);
                        }
                    }
                } //if (psi->lpDependencies)
            } //bResult != FALSE

            CloseServiceHandle(schService);
            schService = NULL;
        } while (FALSE);

        if (psci != NULL)
            supHeapFree(psci);

        if (schService)
            CloseServiceHandle(schService);

        if (SchSCManager)
            CloseServiceHandle(SchSCManager);

        if (bResult == FALSE) {
            EnumChildWindows(hwndDlg, DriverShowChildWindows, SW_HIDE);
            ShowWindow(GetDlgItem(hwndDlg, IDC_QUERYFAIL), SW_SHOW);
        }
        else {
            SetFocus(GetDlgItem(hwndDlg, ID_SERVICE_JUMPTOKEY));
        }

    }
    __except (WOBJ_EXCEPTION_FILTER) {
        EnumChildWindows(hwndDlg, DriverShowChildWindows, SW_HIDE);
        ShowWindow(GetDlgItem(hwndDlg, IDC_QUERYFAIL), SW_SHOW);
        return;
    }
}

/*
* DriverJumpToKey
*
* Purpose:
*
* JumpToKey button handler.
*
*/
VOID DriverJumpToKey(
    _In_ PROP_OBJECT_INFO *Context
)
{
    DWORD             dwProcessId;
    WCHAR            *ch;
    HWND              regeditHwnd, regeditMainHwnd;
    SIZE_T            sz;
    LPWSTR            lpRegPath = NULL;
    HANDLE            hRegeditProcess = NULL;
    SHELLEXECUTEINFO  seinfo;

    WCHAR             szBuffer[MAX_PATH * 2];

    //
    // NtObjectName does not require normalization because regedit cannot handle bogus names anyway.
    //

    do {

        sz = _strlen(Context->NtObjectName.Buffer);
        if (sz == 0)
            break;

        //
        // Create regkeypath buffer to navigate for.
        //
        sz += PROPDRVREGSERVICESKEYLEN;
        sz = (1 + sz) * sizeof(WCHAR);
        lpRegPath = (LPWSTR)supHeapAlloc(sz);
        if (lpRegPath == NULL)
            break;

        _strcpy(lpRegPath, PROPDRVREGSERVICESKEY);
        _strcat(lpRegPath, Context->NtObjectName.Buffer);

        //
        // Start RegEdit.
        //
        // If it already started then open process for sync.
        //
        regeditHwnd = NULL;
        regeditMainHwnd = FindWindow(REGEDITWNDCLASS, NULL);
        if (regeditMainHwnd == NULL) {

            _strcpy(szBuffer, g_WinObj.szWindowsDirectory);
            _strcat(szBuffer, L"\\");
            _strcat(szBuffer, REGEDIT_EXE);

            RtlSecureZeroMemory(&seinfo, sizeof(seinfo));
            seinfo.cbSize = sizeof(seinfo);
            seinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
            seinfo.lpVerb = SHELL_OPEN_VERB;
            seinfo.lpFile = szBuffer;
            seinfo.nShow = SW_SHOWNORMAL;
            ShellExecuteEx(&seinfo);
            hRegeditProcess = seinfo.hProcess;
            if (hRegeditProcess == NULL) {
                break;
            }
            WaitForInputIdle(hRegeditProcess, 10000);
            regeditMainHwnd = FindWindow(REGEDITWNDCLASS, NULL);
        }
        else {
            //
            // Regedit already started, open process for sync.
            //
            dwProcessId = 0;
            GetWindowThreadProcessId(regeditMainHwnd, &dwProcessId);
            hRegeditProcess = OpenProcess(SYNCHRONIZE, FALSE, dwProcessId);
        }

        //
        // Check if we failed to launch regedit.
        //
        if ((hRegeditProcess == NULL) || (regeditMainHwnd == NULL))
            break;

        //
        // Restore regedit window.
        //
        if (IsIconic(regeditMainHwnd)) {
            ShowWindow(regeditMainHwnd, SW_RESTORE);
        }
        else {
            ShowWindow(regeditMainHwnd, SW_SHOW);
        }
        SetForegroundWindow(regeditMainHwnd);
        SetFocus(regeditMainHwnd);
        WaitForInputIdle(hRegeditProcess, 10000);

        //
        // Get treeview window.
        //
        regeditHwnd = FindWindowEx(regeditMainHwnd, NULL, WC_TREEVIEW, NULL);
        if (regeditHwnd == NULL)
            break;

        //
        // Set focus on treeview.
        //
        SetForegroundWindow(regeditHwnd);
        SetFocus(regeditHwnd);

        //
        // Go to the tree root.
        //
        SendMessage(regeditHwnd, WM_KEYDOWN, VK_HOME, 0);

        //
        // Open path, expand if needed, select item.
        //
        for (ch = lpRegPath; *ch; ++ch) {

            if (*ch == L'\\') {
                SendMessage(regeditHwnd, WM_KEYDOWN, VK_RIGHT, 0);
                WaitForInputIdle(hRegeditProcess, 1000);
            }
            else {
#pragma warning(push)
#pragma warning(disable: 4306)
                SendMessage(regeditHwnd,
                    WM_CHAR,
                    (WPARAM)CharUpper((LPWSTR)*ch),
                    (LPARAM)0);
#pragma warning(pop)
                WaitForInputIdle(hRegeditProcess, 1000);
            }
        }

        //
        // Update window focus.
        //
        SetForegroundWindow(regeditMainHwnd);
        SetFocus(regeditMainHwnd);

    } while (FALSE);

    if (lpRegPath) {
        supHeapFree(lpRegPath);
    }
    if (hRegeditProcess) {
        CloseHandle(hRegeditProcess);
    }
}

/*
* DriverRegistryDialogProc
*
* Purpose:
*
* Registry page for Driver object
*
*/
INT_PTR CALLBACK DriverRegistryDialogProc(
    _In_  HWND hwndDlg,
    _In_  UINT uMsg,
    _In_  WPARAM wParam,
    _In_  LPARAM lParam
)
{
    PROPSHEETPAGE    *pSheet = NULL;
    PROP_OBJECT_INFO *Context = NULL;

    switch (uMsg) {

    case WM_SHOWWINDOW:
        if (wParam) {
            Context = (PROP_OBJECT_INFO*)GetProp(hwndDlg, T_PROPCONTEXT);
            DriverSetInfo(Context, hwndDlg);
        }
        return 1;
        break;

    case WM_INITDIALOG:
        pSheet = (PROPSHEETPAGE *)lParam;
        if (pSheet) {
            SetProp(hwndDlg, T_PROPCONTEXT, (HANDLE)pSheet->lParam);
        }
        return 1;
        break;

    case WM_COMMAND:
        if (LOWORD(wParam) == ID_SERVICE_JUMPTOKEY) {
            Context = (PROP_OBJECT_INFO*)GetProp(hwndDlg, T_PROPCONTEXT);
            DriverJumpToKey(Context);
        }
        return 1;
        break;

    case WM_DESTROY:
        RemoveProp(hwndDlg, T_PROPCONTEXT);
        break;
    }
    return 0;
}
