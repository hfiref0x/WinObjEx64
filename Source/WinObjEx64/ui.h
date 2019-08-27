/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019
*
*  TITLE:       UI.H
*
*  VERSION:     1.80
*
*  DATE:        22 June 2019
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

#define PROGRAM_VERSION         L"1.8.0"
#ifdef _USE_OWN_DRIVER
#define PROGRAM_NAME            L"Windows Object Explorer 64-bit (Non-public version)"
#else 
#define PROGRAM_NAME            L"Windows Object Explorer 64-bit"
#endif
#define PROFRAM_NAME_AND_TITLE  L"Object Explorer for Windows 7/8/8.1/10"
#define MAINWINDOWCLASSNAME     L"WinObjEx64Class"
#define PSLISTCLASSNAME         L"winobjex64_pslistdialogclass"

#define T_PROPERTIES            L"Properties...\tEnter"
#define T_GOTOLINKTARGET        L"Go To Link Target\tCtrl+->"
#define T_RUNASADMIN            L"R&un as Administrator"
#define T_RUNASSYSTEM           L"R&un as LocalSystem"
#define T_COPYTEXTROW           L"Copy Row Selection"
#define T_COPYEPROCESS          L"Copy EPROCESS value"
#define T_COPYOBJECT            L"Copy Object value"
#define T_COPYVALUE             L"Copy Value Field Text"
#define T_COPYADDRESS           L"Copy Address Field Text"
#define T_COPYADDINFO           L"Copy Additional Info Field Text"
#define T_SAVETOFILE            L"Save list to File"
#define T_DUMPDRIVER            L"Dump Driver"
#define T_VIEW_REFRESH          L"Refresh\tF5"
#define T_EMPTY                 L" "

typedef enum _WOBJ_DIALOGS_ID {
    wobjFindDlgId = 0,
    wobjIpcPipesDlgId,
    wobjIpcMailSlotsDlgId,
    wobjUSDDlgId,
    wobjPNSDlgId,
    wobjKSSTDlgId,
    wobjW32SSTDlgId,
    wobjPsListDlgId,
    wobjDriversDlgId,
    wobjCallbacksDlgId,
    wobjSLCacheDlgId,
    wobjMaxDlgId
} WOBJ_DIALOGS_ID;

#define MAX_TEXT_CONVERSION_ULONG64 32

//
// Declared in main.c
//
extern HWND g_hwndObjectTree;
extern HWND g_hwndObjectList;
extern HIMAGELIST g_ListViewImages;
extern HIMAGELIST g_ToolBarMenuImages;
extern ATOM g_TreeListAtom;

//
// Declared in propObjectDump.c
//
extern HWND g_TreeList;

typedef struct _TL_SUBITEMS_FIXED {
    ULONG       ColorFlags;
    COLORREF    BgColor;
    COLORREF    FontColor;
    PVOID       UserParam;
    ULONG       Count;
    LPTSTR      Text[2];
} TL_SUBITEMS_FIXED, *PTL_SUBITEMS_FIXED;

//
// Property Dialogs
//

//Variable typedefs

typedef enum _PROP_CONTEXT_TYPE {
    propNormal = 0,
    propPrivateNamespace = 1,
    propUnnamed = 2,
    propMax = 3
} PROP_CONTEXT_TYPE;

typedef struct _PROP_NAMESPACE_INFO {
    ULONG Reserved;
    ULONG SizeOfBoundaryDescriptor;
    OBJECT_BOUNDARY_DESCRIPTOR *BoundaryDescriptor;
    ULONG_PTR ObjectAddress;
} PROP_NAMESPACE_INFO, *PPROP_NAMESPACE_INFO;

typedef struct _PROP_UNNAMED_OBJECT_INFO {
    ULONG_PTR ObjectAddress;
    CLIENT_ID ClientId;
    SYSTEM_THREAD_INFORMATION ThreadInformation;
    UNICODE_STRING ImageName;
} PROP_UNNAMED_OBJECT_INFO, *PPROP_UNNAMED_OBJECT_INFO;

typedef struct _PROP_OBJECT_INFO {
    PROP_CONTEXT_TYPE ContextType;
    BOOL IsType; //TRUE if selected object is an object type
    INT TypeIndex;
    DWORD ObjectFlags;//object specific flags
    LPWSTR lpObjectName;
    LPWSTR lpObjectType;
    LPWSTR lpCurrentObjectPath;
    LPWSTR lpDescription; //description from main list (3rd column)
    ULONG_PTR Tag;
    WOBJ_TYPE_DESC *TypeDescription;
    WOBJ_TYPE_DESC *ShadowTypeDescription; //valid only for types, same as TypeDescription for everything else.
    OBJINFO ObjectInfo; //object dump related structures
    PROP_NAMESPACE_INFO NamespaceInfo;
    PROP_UNNAMED_OBJECT_INFO UnnamedObjectInfo;
} PROP_OBJECT_INFO, *PPROP_OBJECT_INFO;

typedef struct _VALUE_DESC {
    LPWSTR lpDescription;
    DWORD dwValue;
} VALUE_DESC, *PVALUE_DESC;

//Constants
//Display simple "N/A" if no info available
#define T_CannotQuery	TEXT("N/A")

//Display for unknown type value
#define T_UnknownType	TEXT("Unknown Type")
#define T_UnknownFlag	TEXT("Unknown Flag")

//Display for unknown value
#define T_Unknown		TEXT("Unknown")

//prop used by sheets
#define T_PROPCONTEXT	TEXT("propContext")

//prop used by prop dialog
#define T_DLGCONTEXT	TEXT("dlgContext")

//props used by ipc dialogs
#define T_IPCDLGCONTEXT TEXT("IpcDlgContext")

//prop for font
#define T_PROP_FONT TEXT("propFont")

#define T_DEFAULT_AUX_FONT TEXT("Courier New")

//Calendar
static LPCWSTR g_szMonths[12] = {
    L"Jan",
    L"Feb",
    L"Mar",
    L"Apr",
    L"May",
    L"Jun",
    L"Jul",
    L"Aug",
    L"Sep",
    L"Oct",
    L"Nov",
    L"Dec"
};
