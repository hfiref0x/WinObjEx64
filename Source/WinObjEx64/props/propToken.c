/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       PROPTOKEN.C
*
*  VERSION:     1.82
*
*  DATE:        14 Nov 2019
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "propDlg.h"

HWND g_hwndTokenPageList;

#define T_TOKEN_PROP_CID_PID    TEXT("propTokenPid")
#define T_TOKEN_PROP_CID_TID    TEXT("propTokenTid")
#define T_TOKEN_PROP_TYPE       TEXT("propTokenType")


/*
* TokenPageShowError
*
* Purpose:
*
* Hide all windows for given hwnd and display error text with custom text if specified.
*
*/
VOID TokenPageShowError(
    _In_ HWND hwndDlg,
    _In_opt_ LPWSTR lpMessageText
)
{
    ENUMCHILDWNDDATA ChildWndData;

    if (GetWindowRect(hwndDlg, &ChildWndData.Rect)) {
        ChildWndData.nCmdShow = SW_HIDE;
        EnumChildWindows(hwndDlg, supCallbackShowChildWindow, (LPARAM)&ChildWndData);
    }

    if (lpMessageText) {
        SetWindowText(GetDlgItem(hwndDlg, IDC_TOKEN_ERROR), lpMessageText);
    }
    ShowWindow(GetDlgItem(hwndDlg, IDC_TOKEN_ERROR), SW_SHOW);
}

/*
* TokenPageInitControls
*
* Purpose:
*
* Initialize page controls.
*
*/
VOID TokenPageInitControls(
    _In_ HWND hwndDlg,
    _In_ BOOLEAN IsAppContainer
)
{
    LVCOLUMN col;
    LVGROUP lvg;

    g_hwndTokenPageList = GetDlgItem(hwndDlg, IDC_TOKEN_PRIVLIST);

    ListView_SetExtendedListViewStyle(g_hwndTokenPageList,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);

    SendMessage(g_hwndTokenPageList, LVM_ENABLEGROUPVIEW, 1, 0);

    SetWindowTheme(g_hwndTokenPageList, TEXT("Explorer"), NULL);

    RtlSecureZeroMemory(&col, sizeof(col));
    col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH;
    col.iSubItem = 1;
    col.pszText = TEXT("Name");
    col.fmt = LVCFMT_LEFT;
    col.iOrder = 0;
    col.cx = 400;
    ListView_InsertColumn(g_hwndTokenPageList, col.iSubItem, &col);

    col.iSubItem = 2;
    col.pszText = TEXT("Status");
    col.iOrder = 1;
    col.cx = 150;
    ListView_InsertColumn(g_hwndTokenPageList, col.iSubItem, &col);

    RtlSecureZeroMemory(&lvg, sizeof(lvg));
    lvg.cbSize = sizeof(LVGROUP);
    lvg.mask = LVGF_HEADER | LVGF_ALIGN | LVGF_GROUPID;
    lvg.uAlign = LVGA_HEADER_LEFT;

    lvg.pszHeader = TEXT("Privileges");
    lvg.cchHeader = (INT)_strlen(lvg.pszHeader);
    lvg.iGroupId = 0;
    SendMessage(g_hwndTokenPageList, LVM_INSERTGROUP, (WPARAM)0, (LPARAM)&lvg);

    lvg.pszHeader = TEXT("Groups");
    lvg.cchHeader = (INT)_strlen(lvg.pszHeader);
    lvg.iGroupId = 1;
    SendMessage(g_hwndTokenPageList, LVM_INSERTGROUP, (WPARAM)1, (LPARAM)&lvg);

    if (IsAppContainer) {
        lvg.pszHeader = TEXT("Capabilities");
        lvg.cchHeader = (INT)_strlen(lvg.pszHeader);
        lvg.iGroupId = 2;
        SendMessage(g_hwndTokenPageList, LVM_INSERTGROUP, (WPARAM)2, (LPARAM)&lvg);
    }

    SetDlgItemText(hwndDlg, IDC_TOKEN_USER, T_CannotQuery);
    SetDlgItemText(hwndDlg, IDC_TOKEN_SID, T_CannotQuery);
    SetDlgItemText(hwndDlg, IDC_TOKEN_APPCONTAINER, T_CannotQuery);
}

/*
* TokenPageListAdd
*
* Purpose:
*
* Add item to page listview.
*
*/
VOID TokenPageListAdd(
    _In_ INT GroupIndex,
    _In_ LPWSTR lpName,
    _In_ LPWSTR lpStatus
)
{
    INT nIndex;
    LVITEM lvitem;

    RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
    lvitem.mask = LVIF_TEXT | LVIF_GROUPID;
    lvitem.iSubItem = 0;
    lvitem.pszText = lpName;
    lvitem.iItem = MAXINT;
    lvitem.iGroupId = GroupIndex;
    nIndex = ListView_InsertItem(g_hwndTokenPageList, &lvitem);

    lvitem.mask = LVIF_TEXT;
    lvitem.iSubItem = 1;
    lvitem.pszText = lpStatus;
    lvitem.iItem = nIndex;
    ListView_SetItem(g_hwndTokenPageList, &lvitem);
}

/*
* TokenPageListInfo
*
* Purpose:
*
* Query and list token information.
*
*/
VOID TokenPageListInfo(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    BOOLEAN IsAppContainer = FALSE;
    ULONG i, cchName, r;
    NTSTATUS Status;
    LPWSTR ErrMsg = NULL, ElementName, UserAndDomain, pString;
    HANDLE ObjectHandle = NULL;
    HANDLE TokenHandle = NULL;
    ACCESS_MASK DesiredAccessLv1, DesiredAccessLv2;

    PTOKEN_PRIVILEGES pTokenPrivs;
    PTOKEN_USER pTokenUser;
    PTOKEN_MANDATORY_LABEL pTokenIntegrity;
    PTOKEN_GROUPS pTokenGroups;
    PTOKEN_APPCONTAINER_INFORMATION pTokenAppContainer;
    TOKEN_ELEVATION TokenElv;

    WCHAR szBuffer[MAX_PATH], szPrivName[MAX_PATH + 1];

    if (Context->TypeIndex == ObjectTypeProcess) {
        DesiredAccessLv1 = PROCESS_QUERY_INFORMATION;
        DesiredAccessLv2 = PROCESS_QUERY_LIMITED_INFORMATION;
    }
    else {
        DesiredAccessLv1 = THREAD_QUERY_INFORMATION;
        DesiredAccessLv2 = THREAD_QUERY_LIMITED_INFORMATION;
    }

    if (!propOpenCurrentObject(Context, &ObjectHandle, MAXIMUM_ALLOWED)) {
        if (!propOpenCurrentObject(Context, &ObjectHandle, DesiredAccessLv1)) {
            propOpenCurrentObject(Context, &ObjectHandle, DesiredAccessLv2);
        }
    }

    if (ObjectHandle == NULL) {
        TokenPageShowError(hwndDlg, NULL);
        return;
    }

    if (Context->TypeIndex == ObjectTypeProcess) {

        Status = supOpenProcessTokenEx(ObjectHandle, &TokenHandle);
        if (!NT_SUCCESS(Status))
            Status = NtOpenProcessToken(ObjectHandle, TOKEN_QUERY, &TokenHandle);

    }
    else {
        Status = NtOpenThreadToken(ObjectHandle, TOKEN_QUERY, TRUE, &TokenHandle);
    }

    if (NT_SUCCESS(Status) && TokenHandle != NULL) {


        i = 0;
        if (NT_SUCCESS(NtQueryInformationToken(TokenHandle, TokenIsAppContainer, (PVOID)&i, sizeof(ULONG), &r))) {
            IsAppContainer = (i > 0);
        }

        TokenPageInitControls(hwndDlg, IsAppContainer);

        //
        // List token privileges.
        //
        pTokenPrivs = (PTOKEN_PRIVILEGES)supGetTokenInfo(TokenHandle, TokenPrivileges, NULL);
        if (pTokenPrivs) {

            for (i = 0; i < pTokenPrivs->PrivilegeCount; i++) {

                //
                // Output privilege flags like Process Explorer.
                //
                szPrivName[0] = 0;
                cchName = MAX_PATH;
                if (LookupPrivilegeName(NULL, &pTokenPrivs->Privileges[i].Luid,
                    szPrivName, &cchName))
                {
                    ElementName = TEXT("Disabled");
                    if (pTokenPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) {
                        ElementName = TEXT("Enabled");
                    }

                    _strcpy(szBuffer, ElementName);

                    if (pTokenPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) {
                        _strcat(szBuffer, TEXT(", Default Enabled"));
                    }

                    TokenPageListAdd(0, szPrivName, szBuffer);
                }

            }

            supHeapFree(pTokenPrivs);
        }

        //
        // List token groups.
        //
        pTokenGroups = (PTOKEN_GROUPS)supGetTokenInfo(TokenHandle, TokenGroups, NULL);
        if (pTokenGroups) {

            for (i = 0; i < pTokenGroups->GroupCount; i++) {

                UserAndDomain = NULL;
                if (supLookupSidUserAndDomain(pTokenGroups->Groups[i].Sid, &UserAndDomain)) {

                    r = pTokenGroups->Groups[i].Attributes;
                    pString = NULL;
                    szBuffer[0] = 0;
                    if (r & SE_GROUP_USE_FOR_DENY_ONLY)
                        pString = _strcpy(szBuffer, TEXT("Deny"));

                    if (r & SE_GROUP_RESOURCE) {
                        if (pString)
                            _strcat(szBuffer, TEXT(", "));
                        pString = _strcat(szBuffer, TEXT("Domain-Local"));
                    }

                    if ((r & SE_GROUP_MANDATORY) && (!(r & SE_GROUP_OWNER))) {
                        if (pString)
                            _strcat(szBuffer, TEXT(", "));
                        pString = _strcat(szBuffer, TEXT("Mandatory"));
                    }
                    if (r & SE_GROUP_OWNER) {
                        if (pString)
                            _strcat(szBuffer, TEXT(", "));
                        pString = _strcat(szBuffer, TEXT("Owner"));
                    }
                    if (r & SE_GROUP_INTEGRITY) {
                        if (pString)
                            _strcat(szBuffer, TEXT(", "));
                        ElementName = TEXT("Integrity");
                        if (!(r & SE_GROUP_INTEGRITY_ENABLED)) {
                            ElementName = TEXT("DesktopIntegrity");
                        }
                        _strcat(szBuffer, ElementName);
                    }

                    TokenPageListAdd(1, UserAndDomain, szBuffer);

                    supHeapFree(UserAndDomain);
                }

            }

            supHeapFree(pTokenGroups);
        }

        //
        // Token elevated.
        //
        if (NT_SUCCESS(NtQueryInformationToken(TokenHandle, TokenElevation,
            (PVOID)&TokenElv, sizeof(TokenElv), &r)))
        {
            ElementName = (TokenElv.TokenIsElevated > 0) ? TEXT("Yes") : TEXT("No");
            SetDlgItemText(hwndDlg, IDC_TOKEN_ELEVATED, ElementName);
        }

        //
        // Token virtualization.
        //
        i = 0;
        if (NT_SUCCESS(NtQueryInformationToken(TokenHandle, TokenVirtualizationAllowed,
            (PVOID)&i, sizeof(i), &r)))
        {
            if (i > 0) {
                i = 0;
                if (NT_SUCCESS(NtQueryInformationToken(TokenHandle, TokenVirtualizationEnabled,
                    (PVOID)&i, sizeof(i), &r)))
                {
                    ElementName = (i > 0) ? TEXT("Yes") : TEXT("No");
                    SetDlgItemText(hwndDlg, IDC_TOKEN_VIRTUALIZED, ElementName);
                }
            }
        }
        else {
            SetDlgItemText(hwndDlg, IDC_TOKEN_VIRTUALIZED, TEXT("Not allowed"));
        }

        //
        // Token integrity level.
        //
        pTokenIntegrity = (PTOKEN_MANDATORY_LABEL)supGetTokenInfo(TokenHandle, TokenIntegrityLevel, NULL);
        if (pTokenIntegrity) {
            i = *RtlSubAuthoritySid(pTokenIntegrity->Label.Sid,
                (DWORD)(UCHAR)(*RtlSubAuthorityCountSid(pTokenIntegrity->Label.Sid) - 1));
            ElementName = supIntegrityToString(i);
            SetDlgItemText(hwndDlg, IDC_TOKEN_INTEGRITYLEVEL, ElementName);
            supHeapFree(pTokenIntegrity);
        }

        //
        // Token session id.
        //
        i = 0;
        if (NT_SUCCESS(NtQueryInformationToken(TokenHandle, TokenSessionId,
            (PVOID)&i, sizeof(i), &r)))
        {
            szBuffer[0] = 0;
            ultostr(i, szBuffer);
            SetDlgItemText(hwndDlg, IDC_TOKEN_SESSION, szBuffer);
        }

        //
        // Token user.
        //
        pTokenUser = (PTOKEN_USER)supGetTokenInfo(TokenHandle, TokenUser, NULL);
        if (pTokenUser) {
            ElementName = NULL;
            if (ConvertSidToStringSid(pTokenUser->User.Sid, &ElementName)) {
                SetDlgItemText(hwndDlg, IDC_TOKEN_SID, ElementName);
                LocalFree(ElementName);
            }

            ElementName = NULL;
            if (supLookupSidUserAndDomain(pTokenUser->User.Sid, &ElementName)) {
                SetDlgItemText(hwndDlg, IDC_TOKEN_USER, ElementName);
                supHeapFree(ElementName);
            }
            supHeapFree(pTokenUser);
        }

        //
        // AppContainer related.
        //
        if (IsAppContainer) {

            //
            // Token AppContainer SID.
            //
            pTokenAppContainer = (PTOKEN_APPCONTAINER_INFORMATION)supGetTokenInfo(TokenHandle, TokenAppContainerSid, NULL);
            if (pTokenAppContainer) {
                ElementName = NULL;
                if (pTokenAppContainer->TokenAppContainer) {
                    if (ConvertSidToStringSid(pTokenAppContainer->TokenAppContainer, &ElementName)) {
                        SetDlgItemText(hwndDlg, IDC_TOKEN_APPCONTAINER, ElementName);
                        LocalFree(ElementName);
                    }
                }
                supHeapFree(pTokenAppContainer);
            }


            pTokenGroups = (PTOKEN_GROUPS)supGetTokenInfo(TokenHandle, TokenCapabilities, NULL);
            if (pTokenGroups) {

                for (i = 0; i < pTokenGroups->GroupCount; i++) {
                    if (pTokenGroups->Groups[i].Sid) {
                        ElementName = NULL;
                        if (ConvertSidToStringSid(pTokenGroups->Groups[i].Sid, &ElementName)) {
                            TokenPageListAdd(2, ElementName, TEXT("Capabilities"));
                            LocalFree(ElementName);
                        }
                    }
                }
                supHeapFree(pTokenGroups);
            }
        }
        //
        // UIAccess
        //
        i = 0;
        if (NT_SUCCESS(NtQueryInformationToken(TokenHandle, TokenUIAccess,
            (PVOID)&i, sizeof(i), &r)))
        {
            ElementName = (i > 0) ? TEXT("Yes") : TEXT("No");
            SetDlgItemText(hwndDlg, IDC_TOKEN_UIACCESS, ElementName);
        }

        NtClose(TokenHandle);
    }
    else {
        if (Status == STATUS_NO_TOKEN)
            ErrMsg = TEXT("Token doesn't exist, thread is not impersonating a client.");

        TokenPageShowError(hwndDlg, ErrMsg);
    }
    NtClose(ObjectHandle);
}

/*
* TokenPageShowAdvancedProperties
*
* Purpose:
*
* Show properties of selected token object.
*
*/
VOID TokenPageShowAdvancedProperties(
    _In_ HWND hwndDlg)
{
    OBJECT_ATTRIBUTES ObjectAttributes = RTL_INIT_OBJECT_ATTRIBUTES((PUNICODE_STRING)NULL, 0);
    PROP_UNNAMED_OBJECT_INFO TokenObject;
    PROP_DIALOG_CREATE_SETTINGS propSettings;

    LPWSTR TokenStingFormatProcess = TEXT("Process Token, PID:%llu");
    LPWSTR TokenStingFormatThread = TEXT("Thread Token, PID:%llu, TID:%llu");

    HANDLE TokenHandle = NULL;
    WCHAR szFakeName[MAX_PATH + 1];

    //
    // Only one token properties dialog at the same time allowed.
    //
    if (g_PsTokenWindow != NULL) {
        SetActiveWindow(g_PsTokenWindow);
        return;
    }

    RtlSecureZeroMemory(&TokenObject, sizeof(PROP_UNNAMED_OBJECT_INFO));

    TokenObject.ClientId.UniqueProcess =
        GetProp(hwndDlg, T_TOKEN_PROP_CID_PID);

    TokenObject.ClientId.UniqueThread =
        GetProp(hwndDlg, T_TOKEN_PROP_CID_TID);

    TokenObject.IsThreadToken =
        (BOOL)HandleToULong(GetProp(hwndDlg, T_TOKEN_PROP_TYPE));

    RtlSecureZeroMemory(szFakeName, sizeof(szFakeName));

    if (NT_SUCCESS(supOpenTokenByParam(&TokenObject.ClientId,
        &ObjectAttributes,
        TOKEN_QUERY,
        TokenObject.IsThreadToken,
        &TokenHandle)))
    {
        supQueryObjectFromHandle(TokenHandle, &TokenObject.ObjectAddress, NULL);
        NtClose(TokenHandle);
    }

    RtlSecureZeroMemory(&propSettings, sizeof(propSettings));

    if (TokenObject.IsThreadToken) {
        rtl_swprintf_s(szFakeName, MAX_PATH, TokenStingFormatThread,
            TokenObject.ClientId.UniqueProcess,
            TokenObject.ClientId.UniqueThread);
    }
    else {
        rtl_swprintf_s(szFakeName, MAX_PATH, TokenStingFormatProcess,
            TokenObject.ClientId.UniqueProcess);
    }

    propSettings.hwndParent = hwndDlg;
    propSettings.lpObjectName = szFakeName;
    propSettings.lpObjectType = OBTYPE_NAME_TOKEN;
    propSettings.UnnamedObject = &TokenObject;

    propCreateDialog(&propSettings);
}

/*
* TokenPageHandlePopup
*
* Purpose:
*
* Token page list popup construction.
*
*/
VOID TokenPageHandlePopup(
    _In_ HWND hwndDlg,
    _In_ LPPOINT point
)
{
    HMENU hMenu;

    hMenu = CreatePopupMenu();
    if (hMenu) {
        InsertMenu(hMenu, 0, MF_BYCOMMAND, ID_OBJECT_COPY, TEXT("Copy"));
        TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, point->x, point->y, 0, hwndDlg, NULL);
        DestroyMenu(hMenu);
    }
}

/*
* TokenPageDialogOnCommand
*
* Purpose:
*
* Token page WM_COMMAND handler.
*
*/
INT_PTR TokenPageDialogOnCommand(
    _In_ HWND hwndDlg,
    _In_ WPARAM wParam
)
{
    INT_PTR Result = 0;

    switch (LOWORD(wParam)) {
    case ID_OBJECT_COPY:
        supCopyListViewSubItemValue(g_hwndTokenPageList, 0);
        Result = 1;
        break;
    case IDC_TOKEN_ADVANCED:
        TokenPageShowAdvancedProperties(hwndDlg);
        Result = 1;
        break;
    default:
        break;
    }

    return Result;
}

/*
* TokenPageDialogOnInit
*
* Purpose:
*
* Token page WM_INITDIALOG handler.
*
*/
INT_PTR TokenPageDialogOnInit(
    _In_ HWND hwndDlg,
    _In_ LPARAM lParam)
{
    PROPSHEETPAGE    *pSheet = NULL;
    PROP_OBJECT_INFO *Context = NULL;

    pSheet = (PROPSHEETPAGE *)lParam;
    if (pSheet) {
        Context = (PROP_OBJECT_INFO *)pSheet->lParam;

        //
        // Remember client id.
        //
        SetProp(hwndDlg,
            T_TOKEN_PROP_CID_PID,
            Context->UnnamedObjectInfo.ClientId.UniqueProcess);

        SetProp(hwndDlg,
            T_TOKEN_PROP_CID_TID,
            Context->UnnamedObjectInfo.ClientId.UniqueThread);

        SetProp(hwndDlg,
            T_TOKEN_PROP_TYPE,
            UlongToHandle((ULONG)(Context->TypeDescription->Index == ObjectTypeThread)));

        //
        // Show token summary information.
        //
        TokenPageListInfo(Context, hwndDlg);
    }

    return 1;
}

/*
* TokenPageDialogProc
*
* Purpose:
*
* Token page for Process/Thread object type.
*
* WM_INITDIALOG - Initialize listview, set window prop with context,
* collect token info and fill list.
*
*/
INT_PTR CALLBACK TokenPageDialogProc(
    _In_  HWND hwndDlg,
    _In_  UINT uMsg,
    _In_  WPARAM wParam,
    _In_  LPARAM lParam
)
{
    RECT crc;
    INT mark;

    switch (uMsg) {

    case WM_CONTEXTMENU:
        RtlSecureZeroMemory(&crc, sizeof(crc));

        if ((HWND)wParam == g_hwndTokenPageList) {
            mark = ListView_GetSelectionMark(g_hwndTokenPageList);

            if (lParam == MAKELPARAM(-1, -1)) {
                ListView_GetItemRect(g_hwndTokenPageList, mark, &crc, TRUE);
                crc.top = crc.bottom;
                ClientToScreen(g_hwndTokenPageList, (LPPOINT)&crc);
            }
            else
                GetCursorPos((LPPOINT)&crc);

            TokenPageHandlePopup(hwndDlg, (LPPOINT)&crc);

            return 1;
        }
        break;

    case WM_COMMAND:
        return TokenPageDialogOnCommand(hwndDlg, wParam);

    case WM_INITDIALOG:
        return TokenPageDialogOnInit(hwndDlg, lParam);

    case WM_DESTROY:
        RemoveProp(hwndDlg, T_TOKEN_PROP_CID_PID);
        RemoveProp(hwndDlg, T_TOKEN_PROP_CID_TID);
        RemoveProp(hwndDlg, T_TOKEN_PROP_TYPE);
        break;

    default:
        break;
    }
    return 0;
}
