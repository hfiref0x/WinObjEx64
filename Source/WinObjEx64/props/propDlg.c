/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       PROPDLG.C
*
*  VERSION:     1.86
*
*  DATE:        26 May 2020
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "propBasic.h"
#include "propType.h"
#include "propDriver.h"
#include "propToken.h"
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
HWND g_PsPropWindow = NULL;
HWND g_PsTokenWindow = NULL;
HWND g_DesktopPropWindow = NULL;
HWND g_NamespacePropWindow = NULL;

/*
* propCloseCurrentObject
*
* Purpose:
*
* Close handle opened with propOpenCurrentObject.
*
*/
BOOL propCloseCurrentObject(
    _In_ PROP_OBJECT_INFO* Context,
    _In_ HANDLE hObject
)
{
    return supCloseObjectFromContext(Context, hObject);
}

/*
* propOpenCurrentObject
*
* Purpose:
*
* Opens currently viewed object depending on type
*
*/
BOOL propOpenCurrentObject(
    _In_ PROP_OBJECT_INFO* Context,
    _Out_ PHANDLE phObject,
    _In_ ACCESS_MASK DesiredAccess
)
{
    BOOL                bResult;
    HANDLE              hObject, hDirectory;
    NTSTATUS            status;
    UNICODE_STRING      ustr;
    OBJECT_ATTRIBUTES   obja;

    bResult = FALSE;

    *phObject = NULL;

    //
    // Filter unsupported types.
    //
    if (
        (Context->TypeIndex == ObjectTypeUnknown) ||
        (Context->TypeIndex == ObjectTypePort) ||
        (Context->TypeIndex == ObjectTypeFltConnPort) ||
        (Context->TypeIndex == ObjectTypeFltComnPort) ||
        (Context->TypeIndex == ObjectTypeWaitablePort)
        )
    {
        SetLastError(ERROR_UNSUPPORTED_TYPE);
        return bResult;
    }

    //
    // Handle window station type.
    //
    if (Context->TypeIndex == ObjectTypeWinstation) {
        hObject = supOpenWindowStationFromContext(Context, FALSE, DesiredAccess); //WINSTA_READATTRIBUTES for query
        bResult = (hObject != NULL);
        if (bResult) {
            *phObject = hObject;
            SetLastError(ERROR_SUCCESS);
        }
        else {
            SetLastError(ERROR_ACCESS_DENIED);
        }
        return bResult;
    }

    //
    // Handle desktop type.
    //
    if (Context->TypeIndex == ObjectTypeDesktop) {
        if (Context->lpObjectName == NULL) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return bResult;
        }
        hObject = OpenDesktop(Context->lpObjectName, 0, FALSE, DesiredAccess); //DESKTOP_READOBJECTS for query
        bResult = (hObject != NULL);
        if (bResult) {
            *phObject = hObject;
            SetLastError(ERROR_SUCCESS);
        }
        return bResult;
    }

    //
    // Objects without name must be handled in a special way.
    //
    if (Context->ContextType == propUnnamed) {

        InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);

        hObject = supOpenObjectFromContext(
            Context,
            &obja,
            DesiredAccess,
            &status);

        SetLastError(RtlNtStatusToDosError(status));
        bResult = ((NT_SUCCESS(status)) && (hObject != NULL));
        if (bResult) {
            *phObject = hObject;
        }
        return bResult;
    }

    //
    // Namespace objects must be handled in a special way.
    //
    if (Context->ContextType == propPrivateNamespace) {
        if (Context->lpObjectName == NULL) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return bResult;
        }

        RtlInitUnicodeString(&ustr, Context->lpObjectName);
        InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
        hObject = supOpenObjectFromContext(
            Context,
            &obja,
            DesiredAccess,
            &status);

        SetLastError(RtlNtStatusToDosError(status));
        bResult = ((NT_SUCCESS(status)) && (hObject != NULL));
        if (bResult) {
            *phObject = hObject;
        }
        return bResult;
    }

    if ((Context->lpObjectName == NULL) ||
        (Context->lpCurrentObjectPath == NULL)
        )
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return bResult;
    }

    hDirectory = NULL;

    if (DesiredAccess == 0) {
        DesiredAccess = 1;
    }

    //
    // Handle directory type.
    //
    if (Context->TypeIndex == ObjectTypeDirectory) {

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

        hObject = supOpenDirectory(hDirectory, Context->lpObjectName, DesiredAccess);
        bResult = (hObject != NULL);

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
    // Open directory which current object belongs.
    //
    hDirectory = supOpenDirectoryForObject(Context->lpObjectName, Context->lpCurrentObjectPath);
    if (hDirectory == NULL) {
        SetLastError(ERROR_OBJECT_NOT_FOUND);
        return bResult;
    }

    RtlInitUnicodeString(&ustr, Context->lpObjectName);
    InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, hDirectory, NULL);

    status = STATUS_UNSUCCESSFUL;
    hObject = NULL;

    //
    // Handle supported objects.
    //
    hObject = supOpenObjectFromContext(
        Context,
        &obja,
        DesiredAccess,
        &status);

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
    PROP_OBJECT_INFO* Context;

    __try {
        //
        // Allocate context structure.
        //
        Context = (PROP_OBJECT_INFO*)supHeapAlloc(sizeof(PROP_OBJECT_INFO));
        if (Context == NULL)
            return NULL;

        Context->TypeDescription = ObManagerGetEntryByTypeName(lpObjectType);

        //
        // Use the same type descriptor by default for shadow.
        //
        Context->ShadowTypeDescription = Context->TypeDescription;

        //
        // Copy object name if given.
        //
        if (lpObjectName) {

            Context->lpObjectName = (LPWSTR)supHeapAlloc((1 + _strlen(lpObjectName)) * sizeof(WCHAR));
            if (Context->lpObjectName) {
                _strcpy(Context->lpObjectName, lpObjectName);
                bSelectedObject = (_strcmpi(Context->lpObjectName, TEXT("ObjectTypes")) == 0);
            }
        }

        //
        // Copy object type if given.
        //
        if (lpObjectType) {
            Context->lpObjectType = (LPWSTR)supHeapAlloc((1 + _strlen(lpObjectType)) * sizeof(WCHAR));
            if (Context->lpObjectType) {
                _strcpy(Context->lpObjectType, lpObjectType);
            }
            Context->TypeIndex = ObManagerGetIndexByTypeName(lpObjectType);
        }
        else {
            Context->TypeIndex = ObjectTypeUnknown;
        }

        //
        // Copy CurrentObjectPath if given, as it can change because dialog is modeless.
        //
        if (lpCurrentObjectPath) {
            Context->lpCurrentObjectPath = (LPWSTR)supHeapAlloc((1 + _strlen(lpCurrentObjectPath)) * sizeof(WCHAR));
            if (Context->lpCurrentObjectPath) {
                _strcpy(Context->lpCurrentObjectPath, lpCurrentObjectPath);
                bSelectedDirectory = (_strcmpi(Context->lpCurrentObjectPath, T_OBJECTTYPES) == 0);
            }
        }

        //
        // Copy object description, could be NULL.
        //
        if (lpDescription) {
            Context->lpDescription = (LPWSTR)supHeapAlloc((1 + _strlen(lpDescription)) * sizeof(WCHAR));
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
                Context->ShadowTypeDescription = ObManagerGetEntryByTypeName(Context->lpObjectName);
            }

        }

    }
    __except (WOBJ_EXCEPTION_FILTER_LOG) {
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
    _In_ PROP_OBJECT_INFO* Context
)
{
    __try {

        //free associated icons
        supDestroyIconForObjectType(Context);

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
        //free boundary descriptor
        if (Context->ContextType == propPrivateNamespace) {
            if (Context->NamespaceInfo.BoundaryDescriptor) {
                supHeapFree(Context->NamespaceInfo.BoundaryDescriptor);
            }
        }
        //free unnamed object info
        if (Context->ContextType == propUnnamed) {
            if (Context->UnnamedObjectInfo.ImageName.Buffer)
                supHeapFree(Context->UnnamedObjectInfo.ImageName.Buffer);
        }

        //free context itself
        supHeapFree(Context);

    }
    __except (WOBJ_EXCEPTION_FILTER) {
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
    PROP_OBJECT_INFO* Context = NULL;

    switch (Msg) {

    case WM_SYSCOMMAND:
        if (LOWORD(wParam) == SC_CLOSE) {
            SendMessage(hwnd, WM_CLOSE, 0, 0);
        }
        break;

    case WM_DESTROY:
        Context = (PROP_OBJECT_INFO*)GetProp(hwnd, T_PROPCONTEXT);
        if (Context) {
            propContextDestroy(Context);
        }
        RemoveProp(hwnd, T_PROPCONTEXT);
        break;

    case WM_CLOSE:
        if (hwnd == g_PsTokenWindow) {
            g_PsTokenWindow = NULL;
        }
        else if (hwnd == g_PsPropWindow) {
            g_PsPropWindow = NULL;
        }
        else if (hwnd == g_NamespacePropWindow) {
            g_NamespacePropWindow = NULL;
        }
        else if (hwnd == g_DesktopPropWindow) {
            g_DesktopPropWindow = NULL;
        }
        if (hwnd == g_PropWindow) {
            if (g_DesktopPropWindow) {
                g_DesktopPropWindow = NULL;
            }
            //restore previous focus
            if (hPrevFocus) {
                SetFocus(hPrevFocus);
            }
            g_PropWindow = NULL;
        }

        return DestroyWindow(hwnd);
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
* propCopyNamespaceObject
*
* Purpose:
*
* Copy namespace object to the properties context.
*
*/
VOID propCopyNamespaceObject(
    _In_ PROP_OBJECT_INFO* DestinationContext,
    _In_ PROP_NAMESPACE_INFO* NamespaceObject
)
{
    DestinationContext->ContextType = propPrivateNamespace;

    RtlCopyMemory(
        &DestinationContext->NamespaceInfo,
        NamespaceObject,
        sizeof(PROP_NAMESPACE_INFO));
}

/*
* propCopyUnnamedObject
*
* Purpose:
*
* Copy unnamed object to the properties context.
*
*/
VOID propCopyUnnamedObject(
    _In_ PROP_OBJECT_INFO* DestinationContext,
    _In_ PROP_UNNAMED_OBJECT_INFO* SourceObject
)
{
    PVOID CopyBuffer;
    SIZE_T CopySize;

    DestinationContext->ContextType = propUnnamed;

    //
    // Copy generic data.
    //
    DestinationContext->UnnamedObjectInfo.ObjectAddress = SourceObject->ObjectAddress;

    RtlCopyMemory(&DestinationContext->UnnamedObjectInfo.ClientId,
        &SourceObject->ClientId,
        sizeof(CLIENT_ID));

    if (DestinationContext->TypeIndex == ObjectTypeThread) {

        RtlCopyMemory(&DestinationContext->UnnamedObjectInfo.ThreadInformation,
            &SourceObject->ThreadInformation,
            sizeof(SYSTEM_THREAD_INFORMATION));
    }

    //
    // Copy image name if present.
    //
    CopySize = SourceObject->ImageName.MaximumLength;
    if (CopySize) {
        CopyBuffer = supHeapAlloc(CopySize);
        if (CopyBuffer) {

            DestinationContext->UnnamedObjectInfo.ImageName.MaximumLength = (USHORT)CopySize;
            DestinationContext->UnnamedObjectInfo.ImageName.Buffer = (PWSTR)CopyBuffer;

            RtlCopyUnicodeString(&DestinationContext->UnnamedObjectInfo.ImageName,
                &SourceObject->ImageName);

        }
    }
}

/*
* propCreateDialog
*
* Purpose:
*
* Initialize and create PropertySheet Window for selected object properties.
*
* Sets custom Window Procedure for PropertySheet.
*
*/
VOID propCreateDialog(
    _In_ PROP_DIALOG_CREATE_SETTINGS* Settings
)
{
    BOOL              IsSimpleContext = FALSE;
    INT               nPages;
    HWND              hwndDlg;
    PROP_OBJECT_INFO* propContext = NULL;
    HPROPSHEETPAGE    SecurityPage;
    PROPSHEETPAGE     Page;
    PROPSHEETHEADER   PropHeader;
    WCHAR             szCaption[MAX_PATH * 2];

    //
    // Mutual exclusion situation.
    //
    if ((Settings->NamespaceObject != NULL) && (Settings->UnnamedObject != NULL))
        return;

    IsSimpleContext = (Settings->NamespaceObject != NULL) || (Settings->UnnamedObject != NULL);

    //
    // Allocate context variable, copy name, type, object path.
    //
    propContext = propContextCreate(
        Settings->lpObjectName,
        Settings->lpObjectType,
        (IsSimpleContext) ? NULL : g_WinObj.CurrentObjectPath,
        (IsSimpleContext) ? NULL : Settings->lpDescription);

    if (propContext == NULL)
        return;

    //
    // Remember namespace or unnamed object info.
    //
    if (Settings->NamespaceObject) {

        propCopyNamespaceObject(propContext,
            Settings->NamespaceObject);

    }
    else if (Settings->UnnamedObject) {

        propCopyUnnamedObject(propContext,
            Settings->UnnamedObject);

    }

    //
    // Remember previously focused window.
    // Except special types: Desktop.
    //
    if (propContext->TypeIndex != ObjectTypeDesktop) {
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
    case ObjectTypeTimer:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_TIMER);
        break;
    case ObjectTypeMutant:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_MUTANT);
        break;
    case ObjectTypeSemaphore:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_SEMAPHORE);
        break;
    case ObjectTypeJob:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_JOB);
        break;
    case ObjectTypeWinstation:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_WINSTATION);
        break;
    case ObjectTypeEvent:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_EVENT);
        break;
    case ObjectTypeSymbolicLink:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_SYMLINK);
        break;
    case ObjectTypeKey:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_KEY);
        break;
    case ObjectTypeSection:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_SECTION);
        break;
    case ObjectTypeDriver:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_DRIVER);
        break;
    case ObjectTypeDevice:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_DEVICE);
        break;
    case ObjectTypeIoCompletion:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_IOCOMPLETION);
        break;
    case ObjectTypePort:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_ALPCPORT);
        break;
    case ObjectTypeProcess:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_PROCESS);
        break;
    case ObjectTypeThread:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_THREAD);
        break;
    case ObjectTypeToken:
        Page.pszTemplate = MAKEINTRESOURCE(IDD_PROP_TOKEN);
        break;
    case ObjectTypeType:
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
    if (g_kdctx.DeviceHandle != NULL) {
        switch (propContext->TypeIndex) {
        case ObjectTypeDirectory:
        case ObjectTypeDriver:
        case ObjectTypeDevice:
        case ObjectTypeEvent:
        case ObjectTypeMutant:
        case ObjectTypePort:
        case ObjectTypeSemaphore:
        case ObjectTypeTimer:
        case ObjectTypeIoCompletion:
        case ObjectTypeFltConnPort:
        case ObjectTypeType:
        case ObjectTypeCallback:
        case ObjectTypeSymbolicLink:
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
    // Create specific page for Process/Thread objects.
    //
    if ((propContext->TypeIndex == ObjectTypeProcess) ||
        (propContext->TypeIndex == ObjectTypeThread))
    {
        RtlSecureZeroMemory(&Page, sizeof(Page));
        Page.dwSize = sizeof(PROPSHEETPAGE);
        Page.dwFlags = PSP_DEFAULT | PSP_USETITLE;
        Page.hInstance = g_WinObj.hInstance;
        Page.pszTemplate = MAKEINTRESOURCE(IDD_DIALOG_TOKEN);
        Page.pfnDlgProc = TokenPageDialogProc;
        Page.pszTitle = TEXT("Token");
        Page.lParam = (LPARAM)propContext;
        psp[nPages++] = CreatePropertySheetPage(&Page);
    }

    //
    // Create additional page(s), depending on object type.
    //
    switch (propContext->TypeIndex) {
    case ObjectTypeDirectory:
    case ObjectTypePort:
    case ObjectTypeFltComnPort:
    case ObjectTypeFltConnPort:
    case ObjectTypeEvent:
    case ObjectTypeMutant:
    case ObjectTypeSemaphore:
    case ObjectTypeSection:
    case ObjectTypeSymbolicLink:
    case ObjectTypeTimer:
    case ObjectTypeJob:
    case ObjectTypeSession:
    case ObjectTypeIoCompletion:
    case ObjectTypeMemoryPartition:
    case ObjectTypeProcess:
    case ObjectTypeThread:
    case ObjectTypeWinstation:
    case ObjectTypeToken:
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
        if (propContext->TypeIndex == ObjectTypeWinstation) {
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
    case ObjectTypeDriver:
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
        propContext,                                            //Context
        (POPENOBJECTMETHOD)&propOpenCurrentObject,              //OpenObjectMethod
        (PCLOSEOBJECTMETHOD)&propCloseCurrentObject,            //CloseObjectMethod
        SI_EDIT_OWNER | SI_EDIT_PERMS |                         //psiFlags
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
        if (Settings->lpObjectName) {
            _strncpy(szCaption, MAX_PATH, Settings->lpObjectName, _strlen(Settings->lpObjectName));
        }
        else {
            _strcpy(szCaption, TEXT("Unknown Object"));
        }
    }
    else {
        if (Settings->lpObjectType) {
            _strncpy(szCaption, MAX_PATH, Settings->lpObjectType, _strlen(Settings->lpObjectType));
        }
        else {
            _strcpy(szCaption, TEXT("Unknown Type"));
        }
    }

    _strcat(szCaption, TEXT(" Properties"));
    RtlSecureZeroMemory(&PropHeader, sizeof(PropHeader));
    PropHeader.dwSize = sizeof(PropHeader);
    PropHeader.phpage = psp;
    PropHeader.nPages = nPages;
    PropHeader.dwFlags = PSH_DEFAULT | PSH_NOCONTEXTHELP | PSH_MODELESS;
    PropHeader.nStartPage = 0;
    PropHeader.hwndParent = Settings->hwndParent;
    PropHeader.hInstance = g_WinObj.hInstance;
    PropHeader.pszCaption = szCaption;

    hwndDlg = (HWND)PropertySheet(&PropHeader);

    if (hwndDlg) {

        //remove class icon if any
        SetClassLongPtr(hwndDlg, GCLP_HICON, (LONG_PTR)NULL);

        if (propContext->ContextType == propPrivateNamespace) {
            g_NamespacePropWindow = hwndDlg;
        }
        else {

            switch (propContext->TypeIndex) {
            case ObjectTypeProcess:
            case ObjectTypeThread:
                g_PsPropWindow = hwndDlg;
                break;
            case ObjectTypeToken:
                g_PsTokenWindow = hwndDlg;
                break;
            case ObjectTypeDesktop:
                g_DesktopPropWindow = hwndDlg;
                break;
            default:
                g_PropWindow = hwndDlg;
                break;
            }

        }

        SetProp(hwndDlg, T_PROPCONTEXT, (HANDLE)propContext);

        PropSheetOriginalWndProc = (WNDPROC)GetWindowLongPtr(hwndDlg, GWLP_WNDPROC);
        if (PropSheetOriginalWndProc) {
            SetWindowLongPtr(hwndDlg, GWLP_WNDPROC, (LONG_PTR)&PropSheetCustomWndProc);
        }
        supCenterWindow(hwndDlg);
    }
}
