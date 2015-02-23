/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       PROPSECURITY.C
*
*  VERSION:     1.00
*
*  DATE:        19 Feb 2015
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

#pragma comment(lib, "Aclui.lib")

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
		(nTypeIndex != TYPE_JOB)
		)
	{
		return FALSE;
	}
	return TRUE;
}

/*
* propSetSiAccessTable
*
* Purpose:
*
* Set access rights table, generic mappings depending on object type.
*
*/
VOID propSetSiAccessTable(
	IObjectSecurity * This
	)
{
	switch (This->ObjectContext->TypeIndex) {

	case TYPE_DIRECTORY:
		This->dwAccessMax = MAX_KNOWN_DIRECTORY_ACCESS_VALUE;
		This->SiAccessTable	= (PSI_ACCESS)&DirectoryAccessValues;
		break;

	case TYPE_DEVICE:
		This->dwAccessMax = MAX_KNOWN_FILE_ACCESS_VALUE;
		This->SiAccessTable = (PSI_ACCESS)&FileAccessValues;
		break;

	case TYPE_SECTION:
		This->dwAccessMax = MAX_KNOWN_SECTION_ACCESS_VALUE;
		This->SiAccessTable = (PSI_ACCESS)&SectionAccessValues;
		break;

	case TYPE_EVENT:
		This->dwAccessMax = MAX_KNOWN_EVENT_ACCESS_VALUE;
		This->SiAccessTable = (PSI_ACCESS)&EventAccessValues;
		break;

	case TYPE_MUTANT:
		This->dwAccessMax = MAX_KNOWN_MUTANT_ACCESS_VALUE;
		This->SiAccessTable = (PSI_ACCESS)&MutantAccessValues;
		break;

	case TYPE_DESKTOP:
		This->dwAccessMax = MAX_KNOWN_DESKTOP_ACCESS_VALUE;
		This->SiAccessTable = (PSI_ACCESS)&DesktopAccessValues;
		break;

	case TYPE_WINSTATION:
		This->dwAccessMax = MAX_KNOWN_WINSTATION_ACCESS_VALUE;
		This->SiAccessTable = (PSI_ACCESS)&WinStationAccessValues;
		break;

	case TYPE_KEY:
		This->dwAccessMax = MAX_KNOWN_KEY_ACCESS_VALUE;
		This->SiAccessTable = (PSI_ACCESS)&KeyAccessValues;
		break;

	case TYPE_SEMAPHORE:
		This->dwAccessMax = MAX_KNOWN_SEMAPHORE_ACCESS_VALUE;
		This->SiAccessTable = (PSI_ACCESS)&SemaphoreAccessValues;
		break;

	case TYPE_SYMLINK:
		This->dwAccessMax = MAX_KNOWN_SYMLINK_ACCESS_VALUE;
		This->SiAccessTable = (PSI_ACCESS)&SymlinkAccessValues;
		break;

	case TYPE_TIMER:
		This->dwAccessMax = MAX_KNOWN_TIMER_ACCESS_VALUE;
		This->SiAccessTable = (PSI_ACCESS)&TimerAccessValues;
		break;

	case TYPE_JOB:
		This->dwAccessMax = MAX_KNOWN_JOB_ACCESS_VALUE;
		This->SiAccessTable = (PSI_ACCESS)&JobAccessValues;
		break;
	}
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
* propCloseObject
*
* Purpose:
*
* Dereference.
*
*/
VOID propCloseObject(
	_In_ IObjectSecurity * This,
	_In_ HANDLE hObject
	)
{
	if (hObject == NULL) {
		return;
	}
	if (This->ObjectContext->TypeIndex == TYPE_WINSTATION) {
		CloseWindowStation(hObject);
		hObject = NULL;
	}
	if (This->ObjectContext->TypeIndex == TYPE_DESKTOP) {
		CloseDesktop(hObject);
		hObject = NULL;
	}
	if (hObject) {
		NtClose(hObject);
	}
}

HRESULT STDMETHODCALLTYPE QueryInterface(
	IObjectSecurity * This,
	REFIID riid,
	void **ppvObject
	)
{
	if (
		IsEqualIID(riid, &IID_ISecurityInformation) ||
		IsEqualIID(riid, &IID_IUnknown)
		)
	{
		*ppvObject = This;
		This->lpVtbl->AddRef(This);
		return S_OK;
	}

	*ppvObject = NULL;
	return E_NOINTERFACE;
}

ULONG STDMETHODCALLTYPE AddRef(
	IObjectSecurity * This
	)
{
	This->RefCount++;
	return This->RefCount;
}

ULONG STDMETHODCALLTYPE Release(
	IObjectSecurity * This
	)
{
	This->RefCount--;

	if (This->RefCount == 0) {
		if (This->AccessTable) {
			HeapFree(GetProcessHeap(), 0, This->AccessTable);
		}
		HeapFree(GetProcessHeap(), 0, This);
		return S_OK;
	}
	return This->RefCount;
}

HRESULT STDMETHODCALLTYPE GetObjectInformation(
	IObjectSecurity * This,
	PSI_OBJECT_INFO pObjectInfo
	)
{
	pObjectInfo->dwFlags = This->psiFlags;
	pObjectInfo->hInstance = This->hInstance;
	pObjectInfo->pszPageTitle = L"Security";
	pObjectInfo->pszObjectName = This->ObjectContext->lpObjectName;
	return S_OK;
}

HRESULT STDMETHODCALLTYPE GetAccessRights(
	IObjectSecurity * This,
	const GUID* pguidObjectType,
	DWORD dwFlags,
	PSI_ACCESS *ppAccess,
	ULONG *pcAccesses,
	ULONG *piDefaultAccess
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
	IObjectSecurity * This,
	SECURITY_INFORMATION RequestedInformation,
	PSECURITY_DESCRIPTOR *ppSecurityDescriptor,
	BOOL fDefault
	)
{
	HRESULT						hResult;
	HANDLE						hObject;
	ULONG						bytesNeeded;
	NTSTATUS					status;
	ACCESS_MASK					DesiredAccess;

	if (fDefault) {
		return E_NOTIMPL;
	}

	//open object
	hObject = NULL;
	DesiredAccess = propGetObjectAccessMask(RequestedInformation, FALSE);
	if (!propOpenCurrentObject(This->ObjectContext, &hObject, DesiredAccess)) {
		return HRESULT_FROM_WIN32(GetLastError());
	}

	//query object SD
	//warning: system free SD with LocalFree on security dialog destroy
	bytesNeeded = 0x100;
	This->SecurityDescriptor = LocalAlloc(LPTR, bytesNeeded);
	if (This->SecurityDescriptor == NULL) {
		hResult = HRESULT_FROM_WIN32(GetLastError());
		goto Done;
	}

	status = NtQuerySecurityObject(hObject, RequestedInformation, 
		This->SecurityDescriptor, bytesNeeded, &bytesNeeded);

	if (status == STATUS_BUFFER_TOO_SMALL) {
		LocalFree(This->SecurityDescriptor);
		This->SecurityDescriptor = LocalAlloc(LPTR, bytesNeeded);
		if (This->SecurityDescriptor == NULL) {
			hResult = HRESULT_FROM_WIN32(GetLastError());
			goto Done;
		}
		status = NtQuerySecurityObject(
			hObject,
			RequestedInformation,
			This->SecurityDescriptor,
			bytesNeeded,
			&bytesNeeded
			);
	}

	hResult = HRESULT_FROM_WIN32(RtlNtStatusToDosError(status));
	*ppSecurityDescriptor = This->SecurityDescriptor;

Done:
	//cleanup
	propCloseObject(This, hObject);
	return hResult;
}

HRESULT STDMETHODCALLTYPE SetSecurity(
	IObjectSecurity * This,
	SECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR pSecurityDescriptor
	)
{
	HANDLE			hObject = NULL;
	NTSTATUS		status;
	ACCESS_MASK		DesiredAccess;

	DesiredAccess = propGetObjectAccessMask(SecurityInformation, TRUE);
	if (!propOpenCurrentObject(This->ObjectContext, &hObject, DesiredAccess)) {
		return HRESULT_FROM_WIN32(GetLastError());
	}

	status = NtSetSecurityObject(hObject, SecurityInformation, pSecurityDescriptor);

	//cleanup
	propCloseObject(This, hObject);
	return HRESULT_FROM_WIN32(RtlNtStatusToDosError(status));
}

HRESULT STDMETHODCALLTYPE MapGeneric(
	IObjectSecurity * This,
	const GUID *pguidObjectType,
	UCHAR *pAceFlags,
	ACCESS_MASK *pMask
	)
{
	UNREFERENCED_PARAMETER(pguidObjectType);
	UNREFERENCED_PARAMETER(pAceFlags);

	RtlMapGenericMask(pMask, &This->GenericMapping);
	return S_OK;
}

HRESULT STDMETHODCALLTYPE GetInheritTypes(
	IObjectSecurity * This,
	PSI_INHERIT_TYPE *ppInheritTypes,
	ULONG *pcInheritTypes
	)
{
	UNREFERENCED_PARAMETER(This);
	UNREFERENCED_PARAMETER(ppInheritTypes);
	UNREFERENCED_PARAMETER(pcInheritTypes);

	return E_NOTIMPL;
}

HRESULT STDMETHODCALLTYPE PropertySheetPageCallback(
	IObjectSecurity * This,
	HWND hwnd,
	UINT uMsg,
	SI_PAGE_TYPE uPage
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
* Initialize class object, query type info, set Vtbl, Access table.
*
*/
HRESULT propSecurityConstructor(
	IObjectSecurity * This,
	_In_	PROP_OBJECT_INFO *Context,
	_In_	ULONG psiFlags
	)
{
	BOOL cond = FALSE;
	ULONG bytesNeeded;
	SIZE_T Size;
	HRESULT hResult;
	HANDLE hObject = NULL;
	NTSTATUS status;
	POBJECT_TYPE_INFORMATION TypeInfo = NULL;

	do {
		if (!propOpenCurrentObject(Context, &hObject, READ_CONTROL)) {
			hResult = E_ACCESSDENIED;
			break;
		}

		bytesNeeded = 0;
		status = NtQueryObject(hObject, ObjectTypeInformation, NULL, 0, &bytesNeeded);
		if (bytesNeeded == 0) {
			hResult = HRESULT_FROM_WIN32(RtlNtStatusToDosError(status));
			break;
		}

		TypeInfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytesNeeded);
		if (TypeInfo == NULL) {
			hResult = HRESULT_FROM_WIN32(GetLastError());
			break;
		}

		if (!NT_SUCCESS(NtQueryObject(hObject, ObjectTypeInformation, TypeInfo,
			bytesNeeded, &bytesNeeded)))
		{
			hResult = HRESULT_FROM_WIN32(RtlNtStatusToDosError(status));
			break;
		}

		This->GenericMapping = TypeInfo->GenericMapping;
		This->ValidAccessMask = TypeInfo->ValidAccessMask;

		HeapFree(GetProcessHeap(), 0, TypeInfo);
		TypeInfo = NULL;

		This->lpVtbl = &g_Vtbl;
		This->ObjectContext = Context;
		This->hInstance = g_hInstance;
		This->psiFlags = psiFlags;

		propSetSiAccessTable(This);

		//allocate access table
		Size = (MAX_KNOWN_GENERAL_ACCESS_VALUE + This->dwAccessMax) * sizeof(SI_ACCESS);
		This->AccessTable = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
		if (This->AccessTable == NULL) {
			hResult = HRESULT_FROM_WIN32(GetLastError());
			break;
		}

		//copy object specific access table if it present
		if (This->SiAccessTable && This->dwAccessMax) {
			supCopyMemory(This->AccessTable,
				Size,
				This->SiAccessTable,
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
	propCloseObject(This, hObject);
	if (TypeInfo) {
		HeapFree(GetProcessHeap(), 0, TypeInfo);
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
*/
HPROPSHEETPAGE propSecurityCreatePage(
	_In_	PROP_OBJECT_INFO *Context,
	_In_	ULONG psiFlags
	)
{
	IObjectSecurity *psi;

	if (Context == NULL) {
		return NULL;
	}

	if (!propSecurityObjectSupported(Context->TypeIndex)) {
		return NULL;
	}

	psi = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(IObjectSecurity));
	if (psi == NULL) {
		return NULL;
	}

	if (propSecurityConstructor(psi, Context, psiFlags) != S_OK) {
		HeapFree(GetProcessHeap(), 0, psi);
		return NULL;
	}

	return CreateSecurityPage((LPSECURITYINFO)psi);
}