/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2016
*
*  TITLE:       PROPDLG.H
*
*  VERSION:     1.44
*
*  DATE:        17 July 2016
*
*  Common header file for properties dialog.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

//global properties variable type
typedef struct _PROP_OBJECT_INFO {
    BOOL	IsType; //TRUE if selected object is object type
    INT		TypeIndex;
    INT		RealTypeIndex;//save index for type
    DWORD	ObjectFlags;//Object specific flags
    LPWSTR	lpObjectName;
    LPWSTR	lpObjectType;
    LPWSTR  lpCurrentObjectPath;
    LPWSTR	lpDescription; //description from main list (3rd column)
    OBJINFO	ObjectInfo; //object dump related structures
} PROP_OBJECT_INFO, *PPROP_OBJECT_INFO;

typedef struct _VALUE_DESC {
    LPWSTR	lpDescription;
    DWORD	dwValue;
} VALUE_DESC, *PVALUE_DESC;

typedef struct _PROCEDURE_DESC {
    LPWSTR	lpDescription;
    PVOID	Procedure;
} PROCEDURE_DESC, *PPROCEDURE_DESC;

//externs for global properties variables
extern HWND g_PropWindow;
extern HWND g_SubPropWindow;


//Display simple "-" if no info available
#define T_CannotQuery	L"-"

//Display for unknown type value
#define T_UnknownType	L"Unknown Type"
#define T_UnknownFlag	L"Unknown Flag"

//Display for unknown value
#define T_Unknown		L"Unknown"

//prop used by sheets
#define T_PROPCONTEXT	L"propContext"

//prop used by prop dialog
#define T_DLGCONTEXT	L"dlgContext"

/*
** Prototypes
*/

BOOL propOpenCurrentObject(
    _In_	PROP_OBJECT_INFO *Context,
    _Inout_ PHANDLE	phObject,
    _In_	ACCESS_MASK	DesiredAccess
);

VOID propCreateDialog(
    _In_ HWND hwndParent,
    _In_ LPWSTR lpObjectName,
    _In_ LPCWSTR lpObjectType,
    _In_opt_ LPWSTR lpDescription
);

PPROP_OBJECT_INFO propContextCreate(
    LPWSTR lpObjectName,
    LPCWSTR lpObjectType,
    LPWSTR lpCurrentObjectPath,
    LPWSTR lpDescription
);

VOID propContextDestroy(
    PROP_OBJECT_INFO *Context
);
