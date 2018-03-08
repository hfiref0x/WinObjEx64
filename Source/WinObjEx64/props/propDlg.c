/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       PROPDLG.C
*
*  VERSION:     1.53
*
*  DATE:        07 Mar 2018
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "propDlg.h"
#include "propBasic.h"
#include "propType.h"
#include "propDriver.h"
#include "propProcess.h"
#include "propDesktop.h"
#include "propSecurity.h"
#include "propObjectDump.h"

//previously focused window
HWND hPrevFocus;

//maximum number of possible pages, include space reserved for future use
#define MAX_PAGE 10
HPROPSHEETPAGE psp[MAX_PAGE];

//original window procedure of PropertySheet
WNDPROC PropSheetOriginalWndProc = NULL;

//handle to the PropertySheet window
HWND g_PropWindow = NULL;
HWND g_SubPropWindow = NULL;

/*
* propOpenCurrentObject
*
* Purpose:
*
* Opens currently viewed object depending on type
*
*/
BOOL propOpenCurrentObject(
    _In_ PROP_OBJECT_INFO *Context,
    _Out_ PHANDLE phObject,
    _In_ ACCESS_MASK DesiredAccess
)
{
    BOOL                bResult;
    HANDLE              hObject, hDirectory;
    NTSTATUS            status;
    UNICODE_STRING      ustr;
    OBJECT_ATTRIBUTES   obja;
    IO_STATUS_BLOCK     iost;

    bResult = FALSE;

    *phObject = NULL;

    //
    // Filter unsupported types.
    //
    if (
        (Context->TypeIndex == TYPE_UNKNOWN) ||
        (Context->TypeIndex == TYPE_PORT) ||
        (Context->TypeIndex == TYPE_FLTCOMM_PORT) ||
        (Context->TypeIndex == TYPE_FLTCONN_PORT) ||
        (Context->TypeIndex == TYPE_WAITABLEPORT)
        )
    {
        SetLastError(ERROR_UNSUPPORTED_TYPE);
        return bResult;
    }

    if ((Context->lpObjectName == NULL) ||
        (Context->lpCurrentObjectPath == NULL)
        )    
    {
        SetLastError(ERROR_OBJECT_NOT_FOUND);
        return bResult;
    }

    hDirectory = NULL;

    if (DesiredAccess == 0) {
        DesiredAccess = 1;
    }

    //
    // Handle directory type.
    //
    if (Context->TypeIndex == TYPE_DIRECTORY) {

        //
        // If this is root, then root hDirectory = NULL.
        //
        if (_strcmpi(Context->lpObjectName, L"\\") != 0) {
            //
            // Otherwise open directory that keep this object.
            //
            hDirectory = supOpenDirectoryForObject(Context->lpObjectName, Context->lpCurrentObjectPath);
            if (hDirectory == NULL) {
                SetLastError(ERROR_OBJECT_NOT_FOUND);
                return bResult;
            }
        }

        //
        // Open object in directory.
        //
        RtlSecureZeroMemory(&ustr, sizeof(ustr));
        RtlInitUnicodeString(&ustr, Context->lpObjectName);
        InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, hDirectory, NULL);
        hObject = NULL;
        status = NtOpenDirectoryObject(&hObject, DesiredAccess, &obja); //DIRECTORY_QUERY for query

        SetLastError(RtlNtStatusToDosError(status));

        bResult = ((NT_SUCCESS(status)) && (hObject != NULL));
        if (bResult) {
            *phObject = hObject;
        }

        //dont forget to close directory handle if it was opened
        if (hDirectory != NULL) {
            NtClose(hDirectory);
        }
        return bResult;
    }

    //
    // Handle window station type.
    //
    if (Context->TypeIndex == TYPE_WINSTATION) {
        hObject = supOpenWindowStationFromContext(Context, FALSE, DesiredAccess); //WINSTA_READATTRIBUTES for query
        bResult = (hObject != NULL);
        if (bResult) {
            *phObject = hObject;
        }
        return bResult;
    }

    //
    // Handle desktop type.
    //
    if (Context->TypeIndex == TYPE_DESKTOP) {
        hObject = OpenDesktop(Context->lpObjectName, 0, FALSE, DesiredAccess); //DESKTOP_READOBJECTS for query
        bResult = (hObject != NULL);
        if (bResult) {
            *phObject = hObject;
        }
        return bResult;
    }

    //
    // Open directory which current object belongs.
    //
    hDirectory = supOpenDirectoryForObject(Context->lpObjectName, Context->lpCurrentObjectPath);
    if (hDirectory == NULL) {
        SetLastError(ERROR_OBJECT_NOT_FOUND);
        return bResult;
    }

    RtlSecureZeroMemory(&ustr, sizeof(ustr));
    RtlInitUnicodeString(&ustr, Context->lpObjectName);
    InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, hDirectory, NULL);

    status = STATUS_UNSUCCESSFUL;
    hObject = NULL;

    //
    // Handle supported objects.
    //
    switch (Context->TypeIndex) {

    case TYPE_DEVICE: //FILE_OBJECT
        status = NtCreateFile(&hObject, DesiredAccess, &obja, &iost, NULL, 0,
            FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, NULL, 0);//generic access rights
        break;

    case TYPE_MUTANT:
        status = NtOpenMutant(&hObject, DesiredAccess, &obja); //MUTANT_QUERY_STATE for query
        break;

    case TYPE_KEY:
        status = NtOpenKey(&hObject, DesiredAccess, &obja); //KEY_QUERY_VALUE for query
        break;

    case TYPE_SEMAPHORE:
        status = NtOpenSemaphore(&hObject, DesiredAccess, &obja); //SEMAPHORE_QUERY_STATE for query
        break;

    case TYPE_TIMER:
        status = NtOpenTimer(&hObject, DesiredAccess, &obja); //TIMER_QUERY_STATE for query
        break;

    case TYPE_EVENT:
        status = NtOpenEvent(&hObject, DesiredAccess, &obja); //EVENT_QUERY_STATE for query
        break;

    case TYPE_EVENTPAIR:
        status = NtOpenEventPair(&hObject, DesiredAccess, &obja); //generic access
        break;

    case TYPE_SYMLINK:
        status = NtOpenSymbolicLinkObject(&hObject, DesiredAccess, &obja); //SYMBOLIC_LINK_QUERY for query
        break;

    case TYPE_IOCOMPLETION:
        status = NtOpenIoCompletion(&hObject, DesiredAccess, &obja); //IO_COMPLETION_QUERY_STATE for query
        break;

    case TYPE_SECTION:
        status = NtOpenSection(&hObject, DesiredAccess, &obja); //SECTION_QUERY for query
        break;

    case TYPE_JOB:
        status = NtOpenJobObject(&hObject, DesiredAccess, &obja); //JOB_OBJECT_QUERY for query
        break;

    case TYPE_MEMORYPARTITION:
        if (g_ExtApiSet.NtOpenPartition) {
            status = g_ExtApiSet.NtOpenPartition(&hObject, DesiredAccess, &obja); //MEMORY_PARTITION_QUERY_ACCESS for query 
        }
        else
            status = STATUS_PROCEDURE_NOT_FOUND;
        break;
    }
    SetLastError(RtlNtStatusToDosError(status));
    NtClose(hDirectory);

    bResult = ((NT_SUCCESS(status)) && (hObject != NULL));
    if (bResult) {
        *phObject = hObject;
    }
    return bResult;
}

/*
* propContextCreate
*
* Purpose:
*
* Initialize property sheet object context
*
*/
PPROP_OBJECT_INFO propContextCreate(
    _In_opt_ LPWSTR lpObjectName,
    _In_opt_ LPCWSTR lpObjectType,
    _In_opt_ LPWSTR lpCurrentObjectPath,
    _In_opt_ LPWSTR lpDescription
)
{
    BOOL              bSelectedObject = FALSE, bSelectedDirectory = FALSE;
    PROP_OBJECT_INFO *Context;

    __try {
        //
        // Allocate context structure.
        //
        Context = supHeapAlloc(sizeof(PROP_OBJECT_INFO));
        if (Context == NULL)
            return NULL;

        //
        // Copy object name if given.
        //
        if (lpObjectName) {

            Context->lpObjectName = supHeapAlloc((1 + _strlen(lpObjectName)) * sizeof(WCHAR));
            if (Context->lpObjectName) {
                _strcpy(Context->lpObjectName, lpObjectName);
                bSelectedObject = (_strcmpi(Context->lpObjectName, TEXT("ObjectTypes")) == 0);
            }
        }

        //
        // Copy object type if given.
        //
        if (lpObjectType) {
            Context->lpObjectType = supHeapAlloc((1 + _strlen(lpObjectType)) * sizeof(WCHAR));
            if (Context->lpObjectType) {
                _strcpy(Context->lpObjectType, lpObjectType);
            }
            Context->TypeIndex = supGetObjectIndexByTypeName(lpObjectType);
        }

        //
        // Copy CurrentObjectPath if given, as it can change because dialog is modeless.
        //
        if (lpCurrentObjectPath) {
            Context->lpCurrentObjectPath = supHeapAlloc((1 + _strlen(lpCurrentObjectPath)) * sizeof(WCHAR));
            if (Context->lpCurrentObjectPath) {
                _strcpy(Context->lpCurrentObjectPath, lpCurrentObjectPath);
                bSelectedDirectory = (_strcmpi(Context->lpCurrentObjectPath, T_OBJECTTYPES) == 0);
            }
        }
        
        //
        // Copy object description, could be NULL.
        //
        if (lpDescription) {
            Context->lpDescription = supHeapAlloc((1 + _strlen(lpDescription)) * sizeof(WCHAR));
            if (Context->lpDescription) {
                _strcpy(Context->lpDescription, lpDescription);
            }
        }

        //
        // Check if object is Type object.
        // Type objects handled differently.
        //
        if ((bSelectedObject == FALSE) && (bSelectedDirectory != FALSE)) {
            Context->IsType = TRUE;
            //
            // Query actual type index for case when user will browse Type object info.
            //
            if (Context->lpObjectName) {
                Context->RealTypeIndex = supGetObjectIndexByTypeName(Context->lpObjectName);
            }
        }
        else {
            //
            // Use the same type index for everything else.
            //
            Context->RealTypeIndex = Context->TypeIndex;
        }

    }
    __except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
        return NULL;
    }
    return Context;
}

/*
* propContextDestroy
*
* Purpose:
*
* Destroys property sheet object context
*
*/
VOID propContextDestroy(
    _In_ PROP_OBJECT_INFO *Context
)
{
    __try {
        //free name
        if (Context->lpObjectName) {
            supHeapFree(Context->lpObjectName);
        }
        //free type
        if (Context->lpObjectType) {
            supHeapFree(Context->lpObjectType);
        }
        //free currentobjectpath
        if (Context->lpCurrentObjectPath) {
            supHeapFree(Context->lpCurrentObjectPath);
        }
        //free description
        if (Context->lpDescription) {
            supHeapFree(Context->lpDescription);
        }

        //free context itself
        supHeapFree(Context);
    }
    __except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
        return;
    }
}

/*
* PropSheetCustomWndProc
*
* Purpose:
*
* Custom Modeless PropSheet Window Procedure
*
* During WM_DESTROY releases memory allocated for global current object pointers.
*
*/
LRESULT WINAPI PropSheetCustomWndProc(
    _In_ HWND hwnd,
    _In_ UINT Msg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    PROP_OBJECT_INFO *Context = NULL;

    switch (Msg) {

    case WM_SYSCOMMAND:
        if (LOWORD(wParam) == SC_CLOSE) {
            SendMessage(hwnd, WM_CLOSE, 0, 0);
        }
        break;

    case WM_DESTROY:
        Context = GetProp(hwnd, T_PROPCONTEXT);
        propContextDestroy(Context);
        RemoveProp(hwnd, T_PROPCONTEXT);
        break;

    case WM_CLOSE:
        DestroyWindow(hwnd);

        if (hwnd == g_SubPropWindow) {
            g_SubPropWindow = NULL;
        }
        if (hwnd == g_PropWindow) {
            if (g_SubPropWindow) {
                g_SubPropWindow = NULL;
            }
            //restore previous focus
            if (hPrevFocus) {
                SetFocus(hPrevFocus);
            }
            g_PropWindow = NULL;
        }
        return TRUE;
        break;

    case WM_COMMAND:
        if ((LOWORD(wParam) == IDOK) || (LOWORD(wParam) == IDCANCEL)) {
            SendMessage(hwnd, WM_CLOSE, 0, 0);
            return TRUE;
        }
        break;
    default:
        break;
    }
    return CallWindowProc(PropSheetOriginalWndProc, hwnd, Msg, wParam, lParam);
}

/*
* propCreateDialog
*
* Purpose:
*
* Initialize and create PropertySheet Window
*
* Sets custom Window Procedure for PropertySheet
*
*/
VOID propCreateDialog(
    _In_ HWND hwndParent,
    _In_ LPWSTR lpObjectName,
    _In_ LPCWSTR lpObjectType,
    _In_opt_ LPWSTR lpDescription
)
{
    INT                 nPages;
    HWND                hwndDlg;
    PROP_OBJECT_INFO   *propContext = NULL;
    HPROPSHEETPAGE      SecurityPage;
    PROPSHEETPAGE       Page;
    PROPSHEETHEADER     PropHeader;
    WCHAR               szCaption[MAX_PATH * 2];

    //
    // Allocate context variable, copy name, type, object path.
    //
    propContext = propContextCreate(lpObjectName, 
        lpObjectType, 
        g_WinObj.CurrentObjectPath, 
        lpDescription);

    if (propContext == NULL)
        return;

    //
    // If worker available - wait on it.
    //
    if (g_kdctx.hDevice) {
        if (g_kdctx.hThreadWorker) {
            WaitForSingleObject(g_kdctx.hThreadWorker, INFINITE);
            CloseHandle(g_kdctx.hThreadWorker);
            g_kdctx.hThreadWorker = NULL;
        }
    }

    //
    // Remember previously focused window.
    // Except special types: Desktop.
    //
    if (propContext->TypeIndex != TYPE_DESKTOP) {
        hPrevFocus = GetFocus();
    }

    nPages = 0;
    RtlSecureZeroMemory(psp, sizeof(psp));

    //
    // Properties: 
    // Basic->[Object]->[Process]->[Desktops]->[Registry]->Type->[Security]
    //

    //
    // Basic Info Page.
    //
    RtlSecureZeroMemory(&Page, sizeof(Page));
    Page.dwSize = sizeof(PROPSHEETPAGE);
    Page.dwFlags = PSP_DEFAULT | PSP_USETITLE;
    Page.hInstance = g_WinObj.hInstance;

    //
    // Select dialog for basic info.
    //
    switch (propContext->TypeIndex) {
    case TYPE_TIMER:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_TIMER);
        break;
    case TYPE_MUTANT:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_MUTANT);
        break;
    case TYPE_SEMAPHORE:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_SEMAPHORE);
        break;
    case TYPE_JOB:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_JOB);
        break;
    case TYPE_WINSTATION:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_WINSTATION);
        break;
    case TYPE_EVENT:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_EVENT);
        break;
    case TYPE_SYMLINK:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_SYMLINK);
        break;
    case TYPE_KEY:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_KEY);
        break;
    case TYPE_SECTION:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_SECTION);
        break;
    case TYPE_DRIVER:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_DRIVER);
        break;
    case TYPE_DEVICE:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_DEVICE);
        break;
    case TYPE_IOCOMPLETION:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_IOCOMPLETION);
        break;

    case TYPE_TYPE:
    default:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_BASIC);
        break;
    }
    Page.pfnDlgProc = BasicPropDialogProc;
    Page.pszTitle = TEXT("Basic");
    Page.lParam = (LPARAM)propContext;
    psp[nPages++] = CreatePropertySheetPage(&Page);

    //
    // Create Objects page for supported types.
    //
    if (g_kdctx.hDevice != NULL) {
        switch (propContext->TypeIndex) {
        case TYPE_DIRECTORY:
        case TYPE_DRIVER:
        case TYPE_DEVICE:
        case TYPE_EVENT:
        case TYPE_MUTANT:
        case TYPE_SEMAPHORE:
        case TYPE_TIMER:
        case TYPE_IOCOMPLETION:
        case TYPE_FLTCONN_PORT:
        case TYPE_TYPE:
            RtlSecureZeroMemory(&Page, sizeof(Page));
            Page.dwSize = sizeof(PROPSHEETPAGE);
            Page.dwFlags = PSP_DEFAULT | PSP_USETITLE;
            Page.hInstance = g_WinObj.hInstance;
            Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_OBJECTDUMP);
            Page.pfnDlgProc = ObjectDumpDialogProc;
            Page.pszTitle = TEXT("Object");
            Page.lParam = (LPARAM)propContext;
            psp[nPages++] = CreatePropertySheetPage(&Page);
            break;
        }
    }

    //
    // Create additional page(s), depending on object type.
    //
    switch (propContext->TypeIndex) {
    case TYPE_DIRECTORY:
    case TYPE_PORT:
    case TYPE_FLTCOMM_PORT:
    case TYPE_FLTCONN_PORT:
    case TYPE_EVENT:
    case TYPE_MUTANT:
    case TYPE_SEMAPHORE:
    case TYPE_SECTION:
    case TYPE_SYMLINK:
    case TYPE_TIMER:
    case TYPE_JOB:
    case TYPE_WINSTATION:
    case TYPE_IOCOMPLETION:
    case TYPE_MEMORYPARTITION:
        RtlSecureZeroMemory(&Page, sizeof(Page));
        Page.dwSize = sizeof(PROPSHEETPAGE);
        Page.dwFlags = PSP_DEFAULT | PSP_USETITLE;
        Page.hInstance = g_WinObj.hInstance;
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_PROCESSLIST);
        Page.pfnDlgProc = ProcessListDialogProc;
        Page.pszTitle = TEXT("Process");
        Page.lParam = (LPARAM)propContext;
        psp[nPages++] = CreatePropertySheetPage(&Page);

        //
        // Add desktop list for selected desktop, located here because of sheets order.
        //
        if (propContext->TypeIndex == TYPE_WINSTATION) {
            RtlSecureZeroMemory(&Page, sizeof(Page));
            Page.dwSize = sizeof(PROPSHEETPAGE);
            Page.dwFlags = PSP_DEFAULT | PSP_USETITLE;
            Page.hInstance = g_WinObj.hInstance;
            Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_DESKTOPS);
            Page.pfnDlgProc = DesktopListDialogProc;
            Page.pszTitle = TEXT("Desktops");
            Page.lParam = (LPARAM)propContext;
            psp[nPages++] = CreatePropertySheetPage(&Page);
        }

        break;
    case TYPE_DRIVER:
        //
        // Add registry page.
        //
        RtlSecureZeroMemory(&Page, sizeof(Page));
        Page.dwSize = sizeof(PROPSHEETPAGE);
        Page.dwFlags = PSP_DEFAULT | PSP_USETITLE;
        Page.hInstance = g_WinObj.hInstance;
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_SERVICE);
        Page.pfnDlgProc = DriverRegistryDialogProc;
        Page.pszTitle = TEXT("Registry");
        Page.lParam = (LPARAM)propContext;
        psp[nPages++] = CreatePropertySheetPage(&Page);
        break;
    }

    //
    // Type Info Page.
    //
    RtlSecureZeroMemory(&Page, sizeof(Page));
    Page.dwSize = sizeof(PROPSHEETPAGE);
    Page.dwFlags = PSP_DEFAULT | PSP_USETITLE;
    Page.hInstance = g_WinObj.hInstance;
    Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_TYPE);
    Page.pfnDlgProc = TypePropDialogProc;
    Page.pszTitle = TEXT("Type");
    Page.lParam = (LPARAM)propContext;
    psp[nPages++] = CreatePropertySheetPage(&Page);

    //
    // Create Security Dialog if available.
    //
    SecurityPage = propSecurityCreatePage(
        propContext, //Context
        (POPENOBJECTMETHOD)&propOpenCurrentObject, //OpenObjectMethod
        NULL, //CloseObjectMethod, use default
        SI_EDIT_AUDITS | SI_EDIT_OWNER | SI_EDIT_PERMS | //psiFlags
        SI_ADVANCED | SI_NO_ACL_PROTECT | SI_NO_TREE_APPLY |
        SI_PAGE_TITLE
    );
    if (SecurityPage != NULL) {
        psp[nPages++] = SecurityPage;
    }

    //
    // Finally create property sheet.
    //
    if (propContext->IsType) {
        _strncpy(szCaption, MAX_PATH, lpObjectName, _strlen(lpObjectName));
    }
    else {
        _strncpy(szCaption, MAX_PATH, lpObjectType, _strlen(lpObjectType));
    }

    _strcat(szCaption, TEXT(" Properties"));
    RtlSecureZeroMemory(&PropHeader, sizeof(PropHeader));
    PropHeader.dwSize = sizeof(PropHeader);
    PropHeader.phpage = psp;
    PropHeader.nPages = nPages;
    PropHeader.dwFlags = PSH_DEFAULT | PSH_NOCONTEXTHELP | PSH_MODELESS;
    PropHeader.nStartPage = 0;
    PropHeader.hwndParent = hwndParent;
    PropHeader.hInstance = g_WinObj.hInstance;
    PropHeader.pszCaption = szCaption;

    hwndDlg = (HWND)PropertySheet(&PropHeader);

    //remove class icon if any
    SetClassLongPtr(hwndDlg, GCLP_HICON, (LONG_PTR)NULL);

    if (propContext->TypeIndex == TYPE_DESKTOP) {
        g_SubPropWindow = hwndDlg;
    }
    else {
        g_PropWindow = hwndDlg;
    }
    if (hwndDlg) {
        SetProp(hwndDlg, T_PROPCONTEXT, (HANDLE)propContext);
        PropSheetOriginalWndProc = (WNDPROC)GetWindowLongPtr(hwndDlg, GWLP_WNDPROC);
        if (PropSheetOriginalWndProc) {
            SetWindowLongPtr(hwndDlg, GWLP_WNDPROC, (LONG_PTR)&PropSheetCustomWndProc);
        }
        supCenterWindow(hwndDlg);
    }
}
