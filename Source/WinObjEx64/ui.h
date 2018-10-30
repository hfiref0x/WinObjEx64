/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       UI.H
*
*  VERSION:     1.60
*
*  DATE:        24 Oct 2018
*
*  Common header file for the user interface.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define SplitterSize          3
#define SplitterMargin        80

typedef	struct _OE_LIST_ITEM {
    struct _OE_LIST_ITEM *Prev;
    HTREEITEM TreeItem;
} OE_LIST_ITEM, *POE_LIST_ITEM;

typedef HWND(WINAPI *pfnHtmlHelpW)(
    _In_opt_ HWND hwndCaller,
    _In_ LPCWSTR pszFile,
    _In_ UINT uCommand,
    _In_ DWORD_PTR dwData
    );

#define PROGRAM_VERSION         L"1.6.0"
#ifdef _USE_OWN_DRIVER
#define PROGRAM_NAME            L"Windows Object Explorer 64-bit (Non-public version)"
#else 
#define PROGRAM_NAME            L"Windows Object Explorer 64-bit"
#endif
#define PROFRAM_NAME_AND_TITLE  L"Object Explorer for Windows 7/8/8.1/10"
#define MAINWINDOWCLASSNAME     L"WinObjEx64Class"


#define T_PROPERTIES            L"Properties...\tEnter"
#define T_GOTOLINKTARGET        L"Go To Link Target\tCtrl+->"
#define T_RUNASADMIN            L"R&un as Administrator"
#define T_RUNASSYSTEM           L"R&un as LocalSystem"
#define T_COPYTEXTROW           L"Copy Row Selection"
#define T_COPYVALUE             L"Copy Value Field Text"
#define T_COPYADDINFO           L"Copy Additional Info Field Text"
#define T_SAVETOFILE            L"Save list to File"
#define T_DUMPDRIVER            L"Dump Driver"

#define WOBJ_MAX_DIALOGS        7

#define WOBJ_FINDDLG_IDX        0
#define WOBJ_IPCDLG_PIPES_IDX   1
#define WOBJ_IPCDLG_MSLOT_IDX   2
#define WOBJ_USDDLG_IDX         3
#define WOBJ_PNDLG_IDX          4
#define WOBJ_SSDTDLG_IDX        5
#define WOBJ_DRVDLG_IDX         6

#define MAX_TEXT_CONVERSION_ULONG64 32

//
// Global UI variables
//
HWND g_hwndObjectTree;
HWND g_hwndObjectList;
HIMAGELIST g_ListViewImages;
HIMAGELIST g_ToolBarMenuImages;

//
// Treelist
//

HWND g_TreeList;
ATOM g_TreeListAtom;

typedef struct _TL_SUBITEMS_FIXED {
    ULONG       ColorFlags;
    COLORREF    BgColor;
    COLORREF    FontColor;
    ULONG       Count;
    LPTSTR      Text[2];
} TL_SUBITEMS_FIXED, *PTL_SUBITEMS_FIXED;

//
// Property Dialogs
//

//Variable typedefs

typedef struct _PROP_NAMESPACE_INFO {
    ULONG Reserved;
    ULONG SizeOfBoundaryDescriptor;
    OBJECT_BOUNDARY_DESCRIPTOR *BoundaryDescriptor;
    ULONG_PTR ObjectAddress;
} PROP_NAMESPACE_INFO, *PPROP_NAMESPACE_INFO;

typedef struct _PROP_OBJECT_INFO {
    BOOL IsPrivateNamespaceObject;
    BOOL IsType; //TRUE if selected object is object type
    INT TypeIndex;
    INT RealTypeIndex;//save index for type
    DWORD ObjectFlags;//object specific flags
    LPWSTR lpObjectName;
    LPWSTR lpObjectType;
    LPWSTR lpCurrentObjectPath;
    LPWSTR lpDescription; //description from main list (3rd column)
    ULONG_PTR Tag;
    OBJINFO ObjectInfo; //object dump related structures
    PROP_NAMESPACE_INFO NamespaceInfo;
} PROP_OBJECT_INFO, *PPROP_OBJECT_INFO;

typedef struct _VALUE_DESC {
    LPWSTR lpDescription;
    DWORD dwValue;
} VALUE_DESC, *PVALUE_DESC;

typedef struct _PROCEDURE_DESC {
    LPWSTR lpDescription;
    PVOID Procedure;
} PROCEDURE_DESC, *PPROCEDURE_DESC;

//Constants
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

//props used by ipc dialogs
#define T_IPCDLGCONTEXT L"IpcDlgContext"
