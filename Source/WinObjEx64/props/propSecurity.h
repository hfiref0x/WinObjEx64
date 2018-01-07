/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       PROPSECURITY.H
*
*  VERSION:     1.52
*
*  DATE:        08 Jan 2018
*
*  Common header file for Security property sheet.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#include <Aclui.h>
#include <Aclapi.h>

typedef struct _ObjectSecurityVtbl ObjectSecurityVtbl, *PObjectSecurityVtbl;

//custom open object method
typedef BOOL(CALLBACK *POPENOBJECTMETHOD)(
    _In_ PROP_OBJECT_INFO *Context,
    _Inout_ PHANDLE	phObject,
    _In_ ACCESS_MASK DesiredAccess
    );

//future use, currently the same as propDefaultCloseObject
typedef VOID(CALLBACK *PCLOSEOBJECTMETHOD)(
    _In_ PVOID SelfPtrReserved,//do not use
    _In_ HANDLE hObject
    );

//class
typedef struct _IObjectSecurity {
    ObjectSecurityVtbl* lpVtbl;
    ULONG RefCount;
    ULONG psiFlags;
    ULONG dwAccessMax;
    GENERIC_MAPPING GenericMapping;
    ACCESS_MASK ValidAccessMask;
    HINSTANCE hInstance;
    PROP_OBJECT_INFO *ObjectContext;
    PSI_ACCESS AccessTable;//dynamically allocated access table
    POPENOBJECTMETHOD OpenObjectMethod;
    PCLOSEOBJECTMETHOD CloseObjectMethod;
} IObjectSecurity, *PIObjectSecurity;


//Vtbl prototypes

typedef HRESULT(STDMETHODCALLTYPE *pQueryInterface)(
    _In_ IObjectSecurity * This,
    _In_ REFIID riid,
    _Out_ void **ppvObject);

typedef ULONG(STDMETHODCALLTYPE *pAddRef)(
    _In_ IObjectSecurity * This);

typedef ULONG(STDMETHODCALLTYPE *pRelease)(
    _In_ IObjectSecurity * This);

// *** ISecurityInformation methods ***
typedef HRESULT(STDMETHODCALLTYPE *pGetObjectInformation)(
    _In_ IObjectSecurity * This,
    _Out_ PSI_OBJECT_INFO pObjectInfo);

typedef HRESULT(STDMETHODCALLTYPE *pGetSecurity)(
    _In_ IObjectSecurity * This,
    _In_ SECURITY_INFORMATION RequestedInformation,
    _Out_ PSECURITY_DESCRIPTOR *ppSecurityDescriptor,
    _In_ BOOL fDefault);

typedef HRESULT(STDMETHODCALLTYPE *pSetSecurity)(
    _In_ IObjectSecurity * This,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _In_ PSECURITY_DESCRIPTOR pSecurityDescriptor);

typedef HRESULT(STDMETHODCALLTYPE *pGetAccessRights)(
    _In_ IObjectSecurity * This,
    _In_ const GUID* pguidObjectType,
    _In_ DWORD dwFlags,
    _Out_ PSI_ACCESS *ppAccess,
    _Out_ ULONG *pcAccesses,
    _Out_ ULONG *piDefaultAccess);

typedef HRESULT(STDMETHODCALLTYPE *pMapGeneric)(
    _In_ IObjectSecurity * This,
    _In_ const GUID *pguidObjectType,
    _In_ UCHAR *pAceFlags,
    _In_ ACCESS_MASK *pMask);

typedef HRESULT(STDMETHODCALLTYPE *pGetInheritTypes)(
    _In_ IObjectSecurity * This,
    _Out_ PSI_INHERIT_TYPE *ppInheritTypes,
    _Out_ ULONG *pcInheritTypes);

typedef HRESULT(STDMETHODCALLTYPE *pPropertySheetPageCallback)(
    _In_ IObjectSecurity * This,
    _In_ HWND hwnd,
    _In_ UINT uMsg,
    _In_ SI_PAGE_TYPE uPage);

typedef struct _ObjectSecurityVtbl {
    pQueryInterface             QueryInterface;
    pAddRef                     AddRef;
    pRelease                    Release;
    pGetObjectInformation       GetObjectInformation;
    pGetSecurity                GetSecurity;
    pSetSecurity                SetSecurity;
    pGetAccessRights            GetAccessRights;
    pMapGeneric                 MapGeneric;
    pGetInheritTypes            GetInheritTypes;
    pPropertySheetPageCallback  PropertySheetPageCallback;
} ObjectSecurityVtbl, *PObjectSecurityVtbl;

HPROPSHEETPAGE propSecurityCreatePage(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ POPENOBJECTMETHOD OpenObjectMethod,
    _In_opt_ PCLOSEOBJECTMETHOD CloseObjectMethod,
    _In_ ULONG psiFlags);
