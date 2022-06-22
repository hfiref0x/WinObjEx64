/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2022
*
*  TITLE:       PROPDLG.C
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

//previously focused window
HWND PreviousFocus = NULL;

//maximum number of possible pages, include space reserved for future use
#define MAX_PAGE 10
HPROPSHEETPAGE PropPages[MAX_PAGE];

//original window procedure of PropertySheet
WNDPROC PropSheetOriginalWndProc = NULL;

//handle to the PropertySheet window
HWND CommonPropWindow = NULL;
HWND ProcessesPropWindow = NULL;
HWND ThreadsPropWindow = NULL;
HWND TokenPropWindow = NULL;
HWND DesktopPropWindow = NULL;
HWND NamespacePropWindow = NULL;

HWND propGetCommonWindow()
{
    return CommonPropWindow;
}

HWND propGetProcessesWindow()
{
    return ProcessesPropWindow;
}

HWND propGetThreadsWindow()
{
    return ThreadsPropWindow;
}

HWND propGetTokenWindow()
{
    return TokenPropWindow;
}

HWND propGetDesktopWindow()
{
    return DesktopPropWindow;
}

HWND propGetNamespaceWindow()
{
    return NamespacePropWindow;
}

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
* propIsUnsupportedTypeForOpen
*
* Purpose:
*
* Filter object opening by type as we cannot open everything.
*
*/
BOOL propIsUnsupportedTypeForOpen(
    _In_ WOBJ_OBJECT_TYPE TypeIndex
)
{
    WOBJ_OBJECT_TYPE propUnsupportedTypes[] = {
        ObjectTypeUnknown,
        ObjectTypeFltConnPort,
        ObjectTypeFltComnPort,
        ObjectTypeWaitablePort
    };

    ULONG i;
    for (i = 0; i < RTL_NUMBER_OF(propUnsupportedTypes); i++)
        if (TypeIndex == propUnsupportedTypes[i])
            return TRUE;

    return FALSE;
}

/*
* propOpenCurrentObject
*
* Purpose:
*
* Opens currently viewed object depending on type
*
*/
_Success_(return)
BOOL propOpenCurrentObject(
    _In_ PROP_OBJECT_INFO* Context,
    _Out_ PHANDLE phObject,
    _In_ ACCESS_MASK DesiredAccess
)
{
    BOOL bResult;
    HANDLE hObject, hDirectory;
    NTSTATUS status;
    OBJECT_ATTRIBUTES obja;

    bResult = FALSE;

    //
    // Filter unsupported types.
    //
    if (propIsUnsupportedTypeForOpen(Context->ObjectTypeIndex)) {
        SetLastError(ERROR_UNSUPPORTED_TYPE);
        return FALSE;
    }

    //
    // Handle window station type.
    //
    if (Context->ObjectTypeIndex == ObjectTypeWinstation) {
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
    if (Context->ObjectTypeIndex == ObjectTypeDesktop) {

        hObject = OpenDesktop(Context->NtObjectName.Buffer, 0, FALSE, DesiredAccess); //DESKTOP_READOBJECTS for query
        bResult = (hObject != NULL);
        if (bResult) {
            *phObject = hObject;
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

        InitializeObjectAttributes(&obja, &Context->NtObjectName, 
            OBJ_CASE_INSENSITIVE, NULL, NULL);

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

    hDirectory = NULL;

    if (DesiredAccess == 0) {
        DesiredAccess = 1;
    }

    //
    // Handle directory type.
    //
    if (Context->ObjectTypeIndex == ObjectTypeDirectory) {

        //
        // If this is root, then root hDirectory = NULL.
        //
        if (!supIsRootDirectory(&Context->NtObjectName)) {
            //
            // Otherwise open directory that keep this object.
            //
            supOpenDirectoryEx(&hDirectory, NULL, &Context->NtObjectPath, DIRECTORY_QUERY);
            if (hDirectory == NULL) {
                SetLastError(ERROR_OBJECT_NOT_FOUND);
                return bResult;
            }
        }

        //
        // Open object in directory.
        //

        status = supOpenDirectoryEx(&hObject, 
            hDirectory, 
            &Context->NtObjectName, 
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
    supOpenDirectoryEx(&hDirectory, NULL, &Context->NtObjectPath, DIRECTORY_QUERY);
    if (hDirectory == NULL) {
        SetLastError(ERROR_OBJECT_NOT_FOUND);
        return bResult;
    }

    InitializeObjectAttributes(&obja, &Context->NtObjectName, OBJ_CASE_INSENSITIVE, hDirectory, NULL);

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
    _In_ PROP_CONFIG* Config
)
{
    PROP_OBJECT_INFO* propContext;

    union {
        PVOID Ref;
        union {
            PROP_NAMESPACE_INFO* NamespaceObject;
            PROP_UNNAMED_OBJECT_INFO* UnnamedObject;
        };
    } ObjectRef;

    //
    // Allocate context structure.
    //
    propContext = (PROP_OBJECT_INFO*)supHeapAlloc(sizeof(PROP_OBJECT_INFO));
    if (propContext == NULL)
        return NULL;

    propContext->ObjectTypeIndex = Config->ObjectTypeIndex;

    //
    // Copy object name if given.
    //
    if (Config->NtObjectName) {
        supDuplicateUnicodeString(g_obexHeap, &propContext->NtObjectName, Config->NtObjectName);
    }

    //
    // Copy object path if given because dialog is modeless.
    //
    if (Config->NtObjectPath) {
        supDuplicateUnicodeString(g_obexHeap, &propContext->NtObjectPath, Config->NtObjectPath);
    }

    propContext->TypeDescription = ObManagerGetEntryByTypeIndex(propContext->ObjectTypeIndex);

    //
    // Check if object is Type object.
    // Type objects handled differently.
    //
    if (propContext->ObjectTypeIndex == ObjectTypeType) {
        propContext->ShadowTypeDescription = ObManagerGetEntryByTypeName(propContext->NtObjectName.Buffer);
    }
    else {
        //
        // Use the same type descriptor by default for shadow.
        //
        propContext->ShadowTypeDescription = propContext->TypeDescription;
    }

    //
    // Remember namespace or unnamed object info.
    // Always last.
    //
    ObjectRef.Ref = Config->ObjectData;

    if (Config->ContextType == propPrivateNamespace) {

        propContext->ContextType = propPrivateNamespace;
        propContext->u1.NamespaceInfo = *ObjectRef.NamespaceObject;

    }
    else if (Config->ContextType == propUnnamed) {

        propContext->ContextType = propUnnamed;
        //
        // Copy generic data.
        //
        propContext->u1.UnnamedObjectInfo.ObjectAddress = ObjectRef.UnnamedObject->ObjectAddress;
        propContext->u1.UnnamedObjectInfo.ClientId = ObjectRef.UnnamedObject->ClientId;
        if (propContext->ObjectTypeIndex == ObjectTypeThread) {
            propContext->u1.UnnamedObjectInfo.ThreadInformation = ObjectRef.UnnamedObject->ThreadInformation;
        }

        //
        // Copy image name if present.
        //
        supDuplicateUnicodeString(g_obexHeap,
            &propContext->u1.UnnamedObjectInfo.ImageName,
            &ObjectRef.UnnamedObject->ImageName);

    }

    return propContext;
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
    //free associated icons
    if (Context->ObjectTypeIndex == ObjectTypeType) {
        if (Context->ObjectTypeIcon) {
            DestroyIcon(Context->ObjectTypeIcon);
        }
    }
    if (Context->ObjectIcon) {
        DestroyIcon(Context->ObjectIcon);
    }

    //free boundary descriptor
    if (Context->ContextType == propPrivateNamespace) {
        if (Context->u1.NamespaceInfo.BoundaryDescriptor) {
            supHeapFree(Context->u1.NamespaceInfo.BoundaryDescriptor);
        }
    }
    else  if (Context->ContextType == propUnnamed) {
        //free unnamed object info
        supFreeDuplicatedUnicodeString(g_obexHeap, &Context->u1.UnnamedObjectInfo.ImageName, FALSE);
    }

    supFreeDuplicatedUnicodeString(g_obexHeap, &Context->NtObjectName, FALSE);
    supFreeDuplicatedUnicodeString(g_obexHeap, &Context->NtObjectPath, FALSE);

    //free context itself
    supHeapFree(Context);
}

VOID propSetSharedHwnd(
    _In_ HWND hwnd
)
{
    if (hwnd == TokenPropWindow) {
        TokenPropWindow = NULL;
    }
    else if (hwnd == ProcessesPropWindow) {
        if (TokenPropWindow) {
            TokenPropWindow = NULL;
        }
        if (ThreadsPropWindow) {
            ThreadsPropWindow = NULL;
        }
        ProcessesPropWindow = NULL;
    }
    else if (hwnd == ThreadsPropWindow) {
        ThreadsPropWindow = NULL;
    }
    else if (hwnd == NamespacePropWindow) {
        NamespacePropWindow = NULL;
    }
    else if (hwnd == DesktopPropWindow) {
        DesktopPropWindow = NULL;
    }
    if (hwnd == CommonPropWindow) {
        if (DesktopPropWindow) {
            DesktopPropWindow = NULL;
        }
        //restore previous focus
        if (PreviousFocus && IsWindow(PreviousFocus)) {
            SetFocus(PreviousFocus);
        }
        CommonPropWindow = NULL;
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
        propSetSharedHwnd(hwnd);
        DestroyWindow(hwnd);
        break;

    case WM_COMMAND:
        if ((LOWORD(wParam) == IDOK) || (LOWORD(wParam) == IDCANCEL)) {
            SendMessage(hwnd, WM_CLOSE, 0, 0);
            return TRUE;
        }
        break;

    }

    return CallWindowProc(PropSheetOriginalWndProc, hwnd, Msg, wParam, lParam);
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
    switch (Context->ObjectTypeIndex) {
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
        switch (Context->ObjectTypeIndex) {
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
    if ((Context->ObjectTypeIndex == ObjectTypeProcess) ||
        (Context->ObjectTypeIndex == ObjectTypeThread))
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
    switch (Context->ObjectTypeIndex) {
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
    case ObjectTypeRegistryTransaction:
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
        //  WinStation->Basic->Process->[Desktops]->Security
        //
        if (Context->ObjectTypeIndex == ObjectTypeWinstation) {

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
        Context->ObjectTypeIndex == ObjectTypeSection
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
    if (Context->ObjectTypeIndex == ObjectTypePort && IsDriverAssisted) {

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
        Context,                                             //Context
        (POPENOBJECTMETHOD)&propOpenCurrentObject,           //OpenObjectMethod
        (PCLOSEOBJECTMETHOD)&propCloseCurrentObject,         //CloseObjectMethod
        SI_EDIT_OWNER | SI_EDIT_PERMS |                      //psiFlags
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
    _In_ PROP_CONFIG* Config
)
{
    INT nPages;
    HWND hwnd, topLevelOwner;
    PROP_OBJECT_INFO* propContext = NULL;
    PROPSHEETHEADER PropHeader;
    WOBJ_TYPE_DESC* typeEntry;
    WCHAR szCaption[MAX_PATH * 2];

    //
    // Allocate context variable, copy name, type, object path.
    //
    propContext = propContextCreate(Config);
    if (propContext == NULL)
        return;

    //
    // Remember previously focused window.
    // Except special types: Desktop.
    //
    if (propContext->ObjectTypeIndex != ObjectTypeDesktop) {
        PreviousFocus = GetFocus();
    }

    nPages = propCreatePages(propContext);

    //
    // Finally create property sheet.
    //
    if (propContext->ObjectTypeIndex == ObjectTypeType) {

       _strncpy(szCaption, 
           MAX_PATH, 
           propContext->NtObjectName.Buffer, 
           propContext->NtObjectName.Length / sizeof(WCHAR));

    }
    else {
        typeEntry = propContext->TypeDescription;
        if (typeEntry->Index != ObjectTypeUnknown) {
            _strncpy(szCaption, MAX_PATH, typeEntry->Name, _strlen(typeEntry->Name));
        }
        else {
            _strcpy(szCaption, TEXT("Unknown Type"));
        }
    }

    topLevelOwner = Config->hwndParent;

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
        
        propContextDestroy(propContext);
        return;
    }

    if (propContext->ContextType == propPrivateNamespace) {
        NamespacePropWindow = hwnd;
    }
    else {

        switch (propContext->ObjectTypeIndex) {
        case ObjectTypeProcess:
            ProcessesPropWindow = hwnd;
            break;
        case ObjectTypeThread:
            ThreadsPropWindow = hwnd;
            break;
        case ObjectTypeToken:
            TokenPropWindow = hwnd;
            break;
        case ObjectTypeDesktop:
            DesktopPropWindow = hwnd;
            break;
        default:
            CommonPropWindow = hwnd;
            break;
        }

    }

    SetProp(hwnd, T_PROPCONTEXT, (HANDLE)propContext);

    PropSheetOriginalWndProc = (WNDPROC)GetWindowLongPtr(hwnd, GWLP_WNDPROC);
    if (PropSheetOriginalWndProc) {
        SetWindowLongPtr(hwnd, GWLP_WNDPROC, (LONG_PTR)&PropSheetCustomWndProc);
    }

}
