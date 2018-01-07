/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       PROPSECURITY.C
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
#include "propSecurity.h"
#include "propSecurityConsts.h"

/*
* propSecurityObjectSupported
*
* Purpose:
*
* Check we can show security for the given object type.
*
*/
BOOL propSecurityObjectSupported(
    _In_ INT nTypeIndex
)
{
    if (
        (nTypeIndex != TYPE_FILE) &&
        (nTypeIndex != TYPE_DIRECTORY) &&
        (nTypeIndex != TYPE_DEVICE) &&
        (nTypeIndex != TYPE_SECTION) &&
        (nTypeIndex != TYPE_EVENT) &&
        (nTypeIndex != TYPE_MUTANT) &&
        (nTypeIndex != TYPE_DESKTOP) &&
        (nTypeIndex != TYPE_KEY) &&
        (nTypeIndex != TYPE_SEMAPHORE) &&
        (nTypeIndex != TYPE_SYMLINK) &&
        (nTypeIndex != TYPE_TIMER) &&
        (nTypeIndex != TYPE_WINSTATION) &&
        (nTypeIndex != TYPE_IOCOMPLETION) &&
        (nTypeIndex != TYPE_JOB) &&
        (nTypeIndex != TYPE_MEMORYPARTITION)
        )
    {
        return FALSE;
    }
    return TRUE;
}

/*
* propGetAccessTable
*
* Purpose:
*
* Return access rights table and set generic mappings depending on object type.
*
*/
PSI_ACCESS propGetAccessTable(
    _In_ IObjectSecurity * This
)
{
    SI_ACCESS *AccessTable = NULL;

    switch (This->ObjectContext->TypeIndex) {

    case TYPE_DIRECTORY:
        This->dwAccessMax = MAX_KNOWN_DIRECTORY_ACCESS_VALUE;
        AccessTable = (PSI_ACCESS)&DirectoryAccessValues;
        break;

    case TYPE_FILE:
    case TYPE_DEVICE:
        This->dwAccessMax = MAX_KNOWN_FILE_ACCESS_VALUE;
        AccessTable = (PSI_ACCESS)&FileAccessValues;
        break;

    case TYPE_SECTION:
        This->dwAccessMax = MAX_KNOWN_SECTION_ACCESS_VALUE;
        AccessTable = (PSI_ACCESS)&SectionAccessValues;
        break;

    case TYPE_EVENT:
        This->dwAccessMax = MAX_KNOWN_EVENT_ACCESS_VALUE;
        AccessTable = (PSI_ACCESS)&EventAccessValues;
        break;

    case TYPE_MUTANT:
        This->dwAccessMax = MAX_KNOWN_MUTANT_ACCESS_VALUE;
        AccessTable = (PSI_ACCESS)&MutantAccessValues;
        break;

    case TYPE_DESKTOP:
        This->dwAccessMax = MAX_KNOWN_DESKTOP_ACCESS_VALUE;
        AccessTable = (PSI_ACCESS)&DesktopAccessValues;
        break;

    case TYPE_WINSTATION:
        This->dwAccessMax = MAX_KNOWN_WINSTATION_ACCESS_VALUE;
        AccessTable = (PSI_ACCESS)&WinStationAccessValues;
        break;

    case TYPE_KEY:
        This->dwAccessMax = MAX_KNOWN_KEY_ACCESS_VALUE;
        AccessTable = (PSI_ACCESS)&KeyAccessValues;
        break;

    case TYPE_SEMAPHORE:
        This->dwAccessMax = MAX_KNOWN_SEMAPHORE_ACCESS_VALUE;
        AccessTable = (PSI_ACCESS)&SemaphoreAccessValues;
        break;

    case TYPE_SYMLINK:
        This->dwAccessMax = MAX_KNOWN_SYMLINK_ACCESS_VALUE;
        AccessTable = (PSI_ACCESS)&SymlinkAccessValues;
        break;

    case TYPE_TIMER:
        This->dwAccessMax = MAX_KNOWN_TIMER_ACCESS_VALUE;
        AccessTable = (PSI_ACCESS)&TimerAccessValues;
        break;

    case TYPE_JOB:
        This->dwAccessMax = MAX_KNOWN_JOB_ACCESS_VALUE;
        AccessTable = (PSI_ACCESS)&JobAccessValues;
        break;

    case TYPE_IOCOMPLETION:
        This->dwAccessMax = MAX_KNOWN_IOCOMPLETION_ACCESS_VALUE;
        AccessTable = (PSI_ACCESS)&IoCompletionAccessValues;
        break;

    case TYPE_MEMORYPARTITION:
        This->dwAccessMax = MAX_KNOWN_MEMORYPARTITION_ACCESS_VALUE;
        AccessTable = (PSI_ACCESS)&MemoryPartitionAccessValues;
        break;
    }

    return AccessTable;
}

/*
* propGetObjectAccessMask
*
* Purpose:
*
* Query required access mask to get/set object security.
*
*/
ACCESS_MASK propGetObjectAccessMask(
    _In_ SECURITY_INFORMATION SecurityInformation,
    _In_ BOOL fSet
)
{
    ACCESS_MASK AccessMask = 0;

    if (fSet) {
        if (
            (SecurityInformation & OWNER_SECURITY_INFORMATION) ||
            (SecurityInformation & GROUP_SECURITY_INFORMATION)
            )
        {
            AccessMask |= WRITE_OWNER;
        }

        if (SecurityInformation & DACL_SECURITY_INFORMATION) {
            AccessMask |= WRITE_DAC;
        }

        if (SecurityInformation & SACL_SECURITY_INFORMATION) {
            AccessMask |= ACCESS_SYSTEM_SECURITY;
        }
    }
    else {
        //get
        if (
            (SecurityInformation & OWNER_SECURITY_INFORMATION) ||
            (SecurityInformation & GROUP_SECURITY_INFORMATION) ||
            (SecurityInformation & DACL_SECURITY_INFORMATION)
            )
        {
            AccessMask |= READ_CONTROL;
        }

        if (SecurityInformation & SACL_SECURITY_INFORMATION) {
            AccessMask |= ACCESS_SYSTEM_SECURITY;
        }

    }
    return AccessMask;
}

/*
* propDefaultCloseObject
*
* Purpose:
*
* Dereference.
*
*/
VOID propDefaultCloseObject(
    _In_ IObjectSecurity * This,
    _In_ HANDLE hObject
)
{
    if ((hObject != NULL) && (This->ObjectContext)) {
        switch (This->ObjectContext->TypeIndex) {
        case TYPE_WINSTATION:
            CloseWindowStation(hObject);
            break;
        case TYPE_DESKTOP:
            CloseDesktop(hObject);
            break;
        default:
            NtClose(hObject);
            break;
        }
    }
}

HRESULT STDMETHODCALLTYPE QueryInterface(
    _In_ IObjectSecurity * This,
    _In_ REFIID riid,
    _Out_ void **ppvObject
)
{
    if (IsEqualIID(riid, &IID_ISecurityInformation) ||
        IsEqualIID(riid, &IID_IUnknown))
    {
        *ppvObject = This;
        This->lpVtbl->AddRef(This);
        return S_OK;
    }

    *ppvObject = NULL;
    return E_NOINTERFACE;
}

ULONG STDMETHODCALLTYPE AddRef(
    _In_ IObjectSecurity * This
)
{
    This->RefCount++;
    return This->RefCount;
}

ULONG STDMETHODCALLTYPE Release(
    _In_ IObjectSecurity * This
)
{
    This->RefCount--;

    if (This->RefCount == 0) {
        if (This->AccessTable) {
            supHeapFree(This->AccessTable);
        }
        supHeapFree(This);
        return S_OK;
    }
    return This->RefCount;
}

HRESULT STDMETHODCALLTYPE GetObjectInformation(
    _In_ IObjectSecurity * This,
    _Out_ PSI_OBJECT_INFO pObjectInfo
)
{
    pObjectInfo->dwFlags = This->psiFlags;
    pObjectInfo->hInstance = This->hInstance;
    pObjectInfo->pszPageTitle = TEXT("Security");
    pObjectInfo->pszObjectName = This->ObjectContext->lpObjectName;
    return S_OK;
}

HRESULT STDMETHODCALLTYPE GetAccessRights(
    _In_ IObjectSecurity * This,
    _In_ const GUID* pguidObjectType,
    _In_ DWORD dwFlags,
    _Out_ PSI_ACCESS *ppAccess,
    _Out_ ULONG *pcAccesses,
    _Out_ ULONG *piDefaultAccess
)
{
    UNREFERENCED_PARAMETER(pguidObjectType);
    UNREFERENCED_PARAMETER(dwFlags);

    *ppAccess = This->AccessTable;
    *pcAccesses = This->dwAccessMax;
    *piDefaultAccess = 0;

    return S_OK;
}

HRESULT STDMETHODCALLTYPE GetSecurity(
    _In_ IObjectSecurity * This,
    _In_ SECURITY_INFORMATION RequestedInformation,
    _Out_ PSECURITY_DESCRIPTOR *ppSecurityDescriptor,
    _In_ BOOL fDefault
)
{
    HRESULT                hResult;
    HANDLE                 hObject;
    ULONG                  bytesNeeded;
    NTSTATUS               status;
    ACCESS_MASK            DesiredAccess;
    PSECURITY_DESCRIPTOR   PSD;

    if (fDefault) {
        return E_NOTIMPL;
    }

    //open object
    hObject = NULL;
    DesiredAccess = propGetObjectAccessMask(RequestedInformation, FALSE);

    if (!This->OpenObjectMethod(This->ObjectContext, &hObject, DesiredAccess)) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    //query object SD
    //warning: system free SD with LocalFree on security dialog destroy
    bytesNeeded = 0x100;
    PSD = LocalAlloc(LPTR, bytesNeeded);
    if (PSD == NULL) {
        hResult = HRESULT_FROM_WIN32(GetLastError());
        goto Done;
    }

    status = NtQuerySecurityObject(hObject, RequestedInformation,
        PSD, bytesNeeded, &bytesNeeded);

    if (status == STATUS_BUFFER_TOO_SMALL) {
        LocalFree(PSD);
        PSD = LocalAlloc(LPTR, bytesNeeded);
        if (PSD == NULL) {
            hResult = HRESULT_FROM_WIN32(GetLastError());
            goto Done;
        }
        status = NtQuerySecurityObject(
            hObject,
            RequestedInformation,
            PSD,
            bytesNeeded,
            &bytesNeeded
        );
    }

    hResult = HRESULT_FROM_WIN32(RtlNtStatusToDosError(status));
    *ppSecurityDescriptor = PSD;

Done:
    //cleanup
    This->CloseObjectMethod(This, hObject);
    return hResult;
}

HRESULT STDMETHODCALLTYPE SetSecurity(
    _In_ IObjectSecurity * This,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _In_ PSECURITY_DESCRIPTOR pSecurityDescriptor
)
{
    NTSTATUS       status;
    HANDLE         hObject = NULL;
    ACCESS_MASK    DesiredAccess;

    DesiredAccess = propGetObjectAccessMask(SecurityInformation, TRUE);
    if (!This->OpenObjectMethod(This->ObjectContext, &hObject, DesiredAccess)) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    status = NtSetSecurityObject(hObject, SecurityInformation, pSecurityDescriptor);

    //cleanup
    This->CloseObjectMethod(This, hObject);
    return HRESULT_FROM_WIN32(RtlNtStatusToDosError(status));
}

HRESULT STDMETHODCALLTYPE MapGeneric(
    _In_ IObjectSecurity * This,
    _In_ const GUID *pguidObjectType,
    _In_ UCHAR *pAceFlags,
    _In_ ACCESS_MASK *pMask
)
{
    UNREFERENCED_PARAMETER(pguidObjectType);
    UNREFERENCED_PARAMETER(pAceFlags);

    RtlMapGenericMask(pMask, &This->GenericMapping);
    return S_OK;
}

HRESULT STDMETHODCALLTYPE GetInheritTypes(
    _In_ IObjectSecurity * This,
    _Out_ PSI_INHERIT_TYPE *ppInheritTypes,
    _Out_ ULONG *pcInheritTypes
)
{
    UNREFERENCED_PARAMETER(This);
    UNREFERENCED_PARAMETER(ppInheritTypes);
    UNREFERENCED_PARAMETER(pcInheritTypes);

    return E_NOTIMPL;
}

HRESULT STDMETHODCALLTYPE PropertySheetPageCallback(
    _In_ IObjectSecurity * This,
    _In_ HWND hwnd,
    _In_ UINT uMsg,
    _In_ SI_PAGE_TYPE uPage
)
{
    UNREFERENCED_PARAMETER(This);
    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(uMsg);
    UNREFERENCED_PARAMETER(uPage);

    return E_NOTIMPL;
}

//class methods
ObjectSecurityVtbl g_Vtbl = {
    QueryInterface,
    AddRef,
    Release,
    GetObjectInformation,
    GetSecurity,
    SetSecurity,
    GetAccessRights,
    MapGeneric,
    GetInheritTypes,
    PropertySheetPageCallback
};

/*
* propSecurityConstructor
*
* Purpose:
*
* Initialize class object, query type info, Vtbl, AccessTable, object specific methods.
*
*/
HRESULT propSecurityConstructor(
    _In_ IObjectSecurity *This,
    _In_ PROP_OBJECT_INFO *Context,
    _In_ POPENOBJECTMETHOD OpenObjectMethod,
    _In_opt_ PCLOSEOBJECTMETHOD CloseObjectMethod,
    _In_ ULONG psiFlags
)
{
    BOOL                        cond = FALSE;
    ULONG                       bytesNeeded = 0L;
    NTSTATUS                    status;
    SIZE_T                      Size;
    HRESULT                     hResult;
    HANDLE                      hObject = NULL;
    SI_ACCESS                  *TypeAccessTable = NULL;
    POBJECT_TYPE_INFORMATION    TypeInfo = NULL;

    do {
        This->OpenObjectMethod = OpenObjectMethod;

        //if no close method specified, use default
        if (CloseObjectMethod == NULL) {
            This->CloseObjectMethod = propDefaultCloseObject;
        }
        else {
            This->CloseObjectMethod = CloseObjectMethod;
        }

        if (!This->OpenObjectMethod(Context, &hObject, READ_CONTROL)) {
            hResult = E_ACCESSDENIED;
            break;
        }

        bytesNeeded = 0;
        status = NtQueryObject(hObject, ObjectTypeInformation, NULL, 0, &bytesNeeded);
        if (bytesNeeded == 0) {
            hResult = HRESULT_FROM_WIN32(RtlNtStatusToDosError(status));
            break;
        }

        TypeInfo = supHeapAlloc(bytesNeeded);
        if (TypeInfo == NULL) {
            hResult = HRESULT_FROM_WIN32(GetLastError());
            break;
        }

        status = NtQueryObject(hObject, ObjectTypeInformation, TypeInfo,
            bytesNeeded, &bytesNeeded);
        if (!NT_SUCCESS(status)) {
            hResult = HRESULT_FROM_WIN32(RtlNtStatusToDosError(status));
            break;
        }

        This->GenericMapping = TypeInfo->GenericMapping;
        This->ValidAccessMask = TypeInfo->ValidAccessMask;

        supHeapFree(TypeInfo);
        TypeInfo = NULL;

        This->lpVtbl = &g_Vtbl;
        This->ObjectContext = Context;
        This->hInstance = g_WinObj.hInstance;
        This->psiFlags = psiFlags;

        TypeAccessTable = propGetAccessTable(This);

        //allocate access table
        Size = (MAX_KNOWN_GENERAL_ACCESS_VALUE + This->dwAccessMax) * sizeof(SI_ACCESS);
        This->AccessTable = supHeapAlloc(Size);
        if (This->AccessTable == NULL) {
            hResult = HRESULT_FROM_WIN32(GetLastError());
            break;
        }

        //copy object specific access table if it present
        if (TypeAccessTable && This->dwAccessMax) {
            supCopyMemory(This->AccessTable,
                Size,
                TypeAccessTable,
                (This->dwAccessMax * sizeof(SI_ACCESS))
            );
        }

        if (This->ValidAccessMask & DELETE) {
            supCopyMemory(&This->AccessTable[This->dwAccessMax++], sizeof(SI_ACCESS),
                &GeneralAccessValues[0], sizeof(SI_ACCESS));
        }
        if (This->ValidAccessMask & READ_CONTROL) {
            supCopyMemory(&This->AccessTable[This->dwAccessMax++], sizeof(SI_ACCESS),
                &GeneralAccessValues[1], sizeof(SI_ACCESS));
        }
        if (This->ValidAccessMask & WRITE_DAC) {
            supCopyMemory(&This->AccessTable[This->dwAccessMax++], sizeof(SI_ACCESS),
                &GeneralAccessValues[2], sizeof(SI_ACCESS));
        }
        if (This->ValidAccessMask & WRITE_OWNER) {
            supCopyMemory(&This->AccessTable[This->dwAccessMax++], sizeof(SI_ACCESS),
                &GeneralAccessValues[3], sizeof(SI_ACCESS));
        }
        if (This->ValidAccessMask & SYNCHRONIZE) {
            supCopyMemory(&This->AccessTable[This->dwAccessMax++], sizeof(SI_ACCESS),
                &GeneralAccessValues[4], sizeof(SI_ACCESS));
        }
        hResult = S_OK;

    } while (cond);

    //cleanup
    This->CloseObjectMethod(This, hObject);
    if (TypeInfo) {
        supHeapFree(TypeInfo);
    }
    return hResult;
}

/*
* propSecurityCreatePage
*
* Purpose:
*
* Create Security page.
*
*
* Page creation methods call sequence:
* AddRef->QueryInterface->GetObjectInformation->PropertySheetPageCallback.
*
* Page query info call sequence:
* PropertySheetPageCallback->GetObjectInformation->GetAccessRights->GetSecurity->MapGeneric.
*
* Page close call sequence:
* PropertySheetPageCallback->Release.
*
*/
HPROPSHEETPAGE propSecurityCreatePage(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ POPENOBJECTMETHOD OpenObjectMethod,
    _In_opt_ PCLOSEOBJECTMETHOD CloseObjectMethod,
    _In_ ULONG psiFlags
)
{
    IObjectSecurity *psi;

    if (
        (Context == NULL) ||
        (OpenObjectMethod == NULL) //OpenObjectMethod is required
        )
    {
        return NULL;
    }

    if (!propSecurityObjectSupported(Context->TypeIndex)) {
        return NULL;
    }

    psi = supHeapAlloc(sizeof(IObjectSecurity));
    if (psi == NULL)
        return NULL;

    if (propSecurityConstructor(psi, 
        Context,
        OpenObjectMethod, 
        CloseObjectMethod,
        psiFlags) != S_OK)
    {
        supHeapFree(psi);
        return NULL;
    }

    return CreateSecurityPage((LPSECURITYINFO)psi);
}
