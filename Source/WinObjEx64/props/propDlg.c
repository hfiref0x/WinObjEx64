/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2022
*
*  TITLE:       PROPDLG.C
*
*  VERSION:     1.94
*
*  DATE:        06 Jun 2022
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "propAlpcPort.h"
#include "propBasic.h"
#include "propDesktop.h"
#include "propDriver.h"
#include "propObjectDump.h"
#include "propProcess.h"
#include "propSection.h"
#include "propSecurity.h"
#include "propToken.h"
#include "propType.h"

//previously focused window
HWND hPrevFocus;

//maximum number of possible pages, include space reserved for future use
#define MAX_PAGE 10
HPROPSHEETPAGE PropPages[MAX_PAGE];

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
        if (_strcmpi(Context->lpObjectName, KM_OBJECTS_ROOT_DIRECTORY) != 0) {
            //
            // Otherwise open directory that keep this object.
            //
            supOpenDirectoryForObject(&hDirectory, Context->lpObjectName, Context->lpCurrentObjectPath);
            if (hDirectory == NULL) {
                SetLastError(ERROR_OBJECT_NOT_FOUND);
                return bResult;
            }
        }

        //
        // Open object in directory.
        //

        status = supOpenDirectory(&hObject, hDirectory, 
            Context->lpObjectName, 
            DesiredAccess);

        if (!NT_SUCCESS(status)) {
            SetLastError(RtlNtStatusToDosError(status));
        }

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
    supOpenDirectoryForObject(&hDirectory, Context->lpObjectName, Context->lpCurrentObjectPath);
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

        if (Context->PortObjectInfo.IsAllocated) {
            if (Context->PortObjectInfo.ReferenceHandle)
                NtClose(Context->PortObjectInfo.ReferenceHandle);
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
        Context = (PROP_OBJECT_INFO*)RemoveProp(hwnd, T_PROPCONTEXT);
        if (Context) {
            propContextDestroy(Context);
        }
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
            if (hPrevFocus && IsWindow(hPrevFocus)) {
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

HPROPSHEETPAGE propAddPage(
    _In_ LPCWSTR pszTitle,
    _In_ DLGPROC pfnDlgProc,
    _In_ LPCWSTR pszTemplate,
    _In_ LPARAM lParam
)
{
    PROPSHEETPAGE propPage;

    RtlSecureZeroMemory(&propPage, sizeof(propPage));
    propPage.dwSize = sizeof(PROPSHEETPAGE);
    propPage.dwFlags = PSP_DEFAULT | PSP_USETITLE;
    propPage.hInstance = g_WinObj.hInstance;
    propPage.lParam = lParam;
    propPage.pfnDlgProc = pfnDlgProc;
    propPage.pszTemplate = pszTemplate;
    propPage.pszTitle = pszTitle;

    return CreatePropertySheetPage(&propPage);
}

INT propCreatePages(
    _In_ PROP_OBJECT_INFO* Context
)
{
    BOOL IsDriverAssisted;
    INT nPages = 0;
    LPCWSTR pszTemplate;
    HPROPSHEETPAGE hSecurityPage;

    IsDriverAssisted = kdConnectDriver();

    nPages = 0;
    RtlSecureZeroMemory(PropPages, sizeof(PropPages));

    //
    // Properties: 
    // Basic->[Object]->[Process]->[Desktops]->[Registry]->Type->[Security]
    //

    //
    // Basic Info Page.
    //

    //
    // Select dialog for basic info.
    //
    switch (Context->TypeIndex) {
    case ObjectTypeTimer:
        pszTemplate = MAKEINTRESOURCE(IDD_PROP_TIMER);
        break;
    case ObjectTypeMutant:
        pszTemplate = MAKEINTRESOURCE(IDD_PROP_MUTANT);
        break;
    case ObjectTypeSemaphore:
        pszTemplate = MAKEINTRESOURCE(IDD_PROP_SEMAPHORE);
        break;
    case ObjectTypeJob:
        pszTemplate = MAKEINTRESOURCE(IDD_PROP_JOB);
        break;
    case ObjectTypeWinstation:
        pszTemplate = MAKEINTRESOURCE(IDD_PROP_WINSTATION);
        break;
    case ObjectTypeEvent:
        pszTemplate = MAKEINTRESOURCE(IDD_PROP_EVENT);
        break;
    case ObjectTypeSymbolicLink:
        pszTemplate = MAKEINTRESOURCE(IDD_PROP_SYMLINK);
        break;
    case ObjectTypeKey:
        pszTemplate = MAKEINTRESOURCE(IDD_PROP_KEY);
        break;
    case ObjectTypeSection:
        pszTemplate = MAKEINTRESOURCE(IDD_PROP_SECTION);
        break;
    case ObjectTypeDriver:
        pszTemplate = MAKEINTRESOURCE(IDD_PROP_DRIVER);
        break;
    case ObjectTypeDevice:
        pszTemplate = MAKEINTRESOURCE(IDD_PROP_DEVICE);
        break;
    case ObjectTypeIoCompletion:
        pszTemplate = MAKEINTRESOURCE(IDD_PROP_IOCOMPLETION);
        break;
    case ObjectTypePort:
        pszTemplate = MAKEINTRESOURCE(IDD_PROP_ALPCPORT);
        break;
    case ObjectTypeProcess:
        pszTemplate = MAKEINTRESOURCE(IDD_PROP_PROCESS);
        break;
    case ObjectTypeThread:
        pszTemplate = MAKEINTRESOURCE(IDD_PROP_THREAD);
        break;
    case ObjectTypeToken:
        pszTemplate = MAKEINTRESOURCE(IDD_PROP_TOKEN);
        break;
    case ObjectTypeType:
    default:
        pszTemplate = MAKEINTRESOURCE(IDD_PROP_BASIC);
        break;
    }

    PropPages[nPages++] = propAddPage(
        TEXT("Basic"),
        BasicPropDialogProc,
        pszTemplate,
        (LPARAM)Context);

    //
    // Create Objects page for supported types.
    //
    if (IsDriverAssisted) {
        switch (Context->TypeIndex) {
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

            PropPages[nPages++] = propAddPage(
                TEXT("Object"),
                ObjectDumpDialogProc,
                MAKEINTRESOURCE(IDD_PROP_OBJECTDUMP),
                (LPARAM)Context);

            break;
        }
    }

    //
    // Create specific page for Process/Thread objects.
    //
    if ((Context->TypeIndex == ObjectTypeProcess) ||
        (Context->TypeIndex == ObjectTypeThread))
    {
        PropPages[nPages++] = propAddPage(
            TEXT("Token"),
            TokenPageDialogProc,
            MAKEINTRESOURCE(IDD_DIALOG_TOKEN),
            (LPARAM)Context);
    }

    //
    // Create additional page(s), depending on object type.
    //
    switch (Context->TypeIndex) {
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

        PropPages[nPages++] = propAddPage(
            TEXT("Process"),
            ProcessListDialogProc,
            MAKEINTRESOURCE(IDD_PROP_PROCESSLIST),
            (LPARAM)Context);

        //
        // Add desktop list for selected desktop, located here because of sheets order.
        //
        if (Context->TypeIndex == ObjectTypeWinstation) {

            PropPages[nPages++] = propAddPage(
                TEXT("Desktops"),
                DesktopListDialogProc,
                MAKEINTRESOURCE(IDD_PROP_DESKTOPS),
                (LPARAM)Context);
        }

        break;
    case ObjectTypeDriver:
        //
        // Add registry page.
        //
        PropPages[nPages++] = propAddPage(
            TEXT("Registry"),
            DriverRegistryDialogProc,
            MAKEINTRESOURCE(IDD_PROP_SERVICE),
            (LPARAM)Context);

        break;
    }

    //
    // Add Section object specific page, driver assistance required.
    //
    // This feature implemented only for Windows 10 as structures are too variable.
    //

    if (g_NtBuildNumber >= NT_WIN10_THRESHOLD1 &&
        Context->TypeIndex == ObjectTypeSection
        && IsDriverAssisted)
    {
        PropPages[nPages++] = propAddPage(
            TEXT("Object"),
            SectionPropertiesDialogProc,
            MAKEINTRESOURCE(IDD_PROP_OBJECTDUMP),
            (LPARAM)Context);
    }

    //
    // Add ALPC port specific page, driver assistance required.
    //
    if (Context->TypeIndex == ObjectTypePort && IsDriverAssisted) {

        PropPages[nPages++] = propAddPage(
            TEXT("Connections"),
            AlpcPortListDialogProc,
            MAKEINTRESOURCE(IDD_PROP_ALPCPORTLIST),
            (LPARAM)Context);
    }

    //
    // Type Info Page.
    //
    PropPages[nPages++] = propAddPage(
        TEXT("Type"),
        TypePropDialogProc,
        MAKEINTRESOURCE(IDD_PROP_TYPE),
        (LPARAM)Context);

    //
    // Create Security Dialog if available.
    //
    hSecurityPage = propSecurityCreatePage(
        Context,                                            //Context
        (POPENOBJECTMETHOD)&propOpenCurrentObject,              //OpenObjectMethod
        (PCLOSEOBJECTMETHOD)&propCloseCurrentObject,            //CloseObjectMethod
        SI_EDIT_OWNER | SI_EDIT_PERMS |                         //psiFlags
        SI_ADVANCED | SI_NO_ACL_PROTECT | SI_NO_TREE_APPLY |
        SI_PAGE_TITLE
    );
    if (hSecurityPage != NULL) {
        PropPages[nPages++] = hSecurityPage;
    }

    return nPages;
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
    HWND              hwnd, topLevelOwner;
    PROP_OBJECT_INFO* propContext = NULL;
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

    nPages = propCreatePages(propContext);

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

    topLevelOwner = Settings->hwndParent;

    _strcat(szCaption, TEXT(" Properties"));
    RtlSecureZeroMemory(&PropHeader, sizeof(PropHeader));
    PropHeader.dwSize = sizeof(PropHeader);
    PropHeader.phpage = PropPages;
    PropHeader.nPages = nPages;
    PropHeader.nStartPage = 0;
    PropHeader.dwFlags = PSH_NOCONTEXTHELP | PSH_MODELESS | PSH_USEPSTARTPAGE;
    PropHeader.hwndParent = topLevelOwner;
    PropHeader.hInstance = g_WinObj.hInstance;
    PropHeader.pszCaption = szCaption;

    hwnd = (HWND)PropertySheet(&PropHeader);

    if (!hwnd) {
        if (topLevelOwner)
            EnableWindow(topLevelOwner, TRUE);
        return;
    }

    if (propContext->ContextType == propPrivateNamespace) {
        g_NamespacePropWindow = hwnd;
    }
    else {

        switch (propContext->TypeIndex) {
        case ObjectTypeProcess:
        case ObjectTypeThread:
            g_PsPropWindow = hwnd;
            break;
        case ObjectTypeToken:
            g_PsTokenWindow = hwnd;
            break;
        case ObjectTypeDesktop:
            g_DesktopPropWindow = hwnd;
            break;
        default:
            g_PropWindow = hwnd;
            break;
        }

    }

    SetProp(hwnd, T_PROPCONTEXT, (HANDLE)propContext);

    PropSheetOriginalWndProc = (WNDPROC)GetWindowLongPtr(hwnd, GWLP_WNDPROC);
    if (PropSheetOriginalWndProc) {
        SetWindowLongPtr(hwnd, GWLP_WNDPROC, (LONG_PTR)&PropSheetCustomWndProc);
    }

    supCenterWindow(hwnd);
}
