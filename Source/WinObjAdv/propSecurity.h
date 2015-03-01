/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       PROPSECURITY.H
*
*  VERSION:     1.10
*
*  DATE:        25 Feb 2015
*
*  Common header file for Security property sheet.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include <Aclui.h>
#include <Aclapi.h>

typedef struct _ObjectSecurityVtbl ObjectSecurityVtbl, *PObjectSecurityVtbl;

//custom open object method
typedef BOOL(CALLBACK *POPENOBJECTMETHOD)(
	_In_	PROP_OBJECT_INFO *Context,
	_Inout_ PHANDLE	phObject,
	_In_	ACCESS_MASK	DesiredAccess
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

typedef HRESULT(STDMETHODCALLTYPE *pQueryInterface)(IObjectSecurity * This, REFIID riid, void **ppvObject);
typedef ULONG(STDMETHODCALLTYPE *pAddRef)(IObjectSecurity * This);
typedef ULONG(STDMETHODCALLTYPE *pRelease)(IObjectSecurity * This);

// *** ISecurityInformation methods ***
typedef HRESULT(STDMETHODCALLTYPE *pGetObjectInformation)(IObjectSecurity * This, PSI_OBJECT_INFO pObjectInfo);

typedef HRESULT(STDMETHODCALLTYPE *pGetSecurity)(IObjectSecurity * This, SECURITY_INFORMATION RequestedInformation,
	PSECURITY_DESCRIPTOR *ppSecurityDescriptor, BOOL fDefault);

typedef HRESULT(STDMETHODCALLTYPE *pSetSecurity)(IObjectSecurity * This, SECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR pSecurityDescriptor);

typedef HRESULT(STDMETHODCALLTYPE *pGetAccessRights)(IObjectSecurity * This, const GUID* pguidObjectType,
	DWORD dwFlagsB, PSI_ACCESS *ppAccess, ULONG *pcAccesses, ULONG *piDefaultAccess);

typedef HRESULT(STDMETHODCALLTYPE *pMapGeneric)(IObjectSecurity * This, const GUID *pguidObjectType,
	UCHAR *pAceFlags, ACCESS_MASK *pMask);

typedef HRESULT(STDMETHODCALLTYPE *pGetInheritTypes)(IObjectSecurity * This, PSI_INHERIT_TYPE *ppInheritTypes,
	ULONG *pcInheritTypes);

typedef HRESULT(STDMETHODCALLTYPE *pPropertySheetPageCallback)(IObjectSecurity * This, HWND hwnd,
	UINT uMsg, SI_PAGE_TYPE uPage);

typedef struct _ObjectSecurityVtbl {
	pQueryInterface				QueryInterface;
	pAddRef						AddRef;
	pRelease					Release;
	pGetObjectInformation		GetObjectInformation;
	pGetSecurity				GetSecurity;
	pSetSecurity				SetSecurity;
	pGetAccessRights			GetAccessRights;
	pMapGeneric					MapGeneric;
	pGetInheritTypes			GetInheritTypes;
	pPropertySheetPageCallback	PropertySheetPageCallback;
} ObjectSecurityVtbl, *PObjectSecurityVtbl;

HPROPSHEETPAGE propSecurityCreatePage(
	_In_		PROP_OBJECT_INFO *Context,
	_In_		POPENOBJECTMETHOD OpenObjectMethod,
	_In_opt_	PCLOSEOBJECTMETHOD CloseObjectMethod,
	_In_		ULONG psiFlags
	);