/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       UI.H
*
*  VERSION:     1.84
*
*  DATE:        29 Feb 2020
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

#define SCALE_DPI_VALUE(Value) MulDiv(Value, g_CurrentDPI, DefaultSystemDpi)

#define SplitterSize                3
#define SplitterMargin              80

#define DefaultSystemDpi            96
#define TreeListDumpObjWndPosX      12
#define TreeListDumpObjWndPosY      20
#define TreeListDumpObjWndScaleSub  3

//
// ListView column counts
//

#define MAIN_OBJLIST_COLUMN_COUNT 3
#define FINDLIST_COLUMN_COUNT 2
#define DRVLIST_COLUMN_COUNT 5
#define PROCESSLIST_COLUMN_COUNT 4
#define PNLIST_COLUMN_COUNT 3
#define PSLIST_COLUMN_COUNT 6
#define SSDTLIST_COLUMN_COUNT 4
#define SLLIST_COLUMN_COUNT 2


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

#define PROGRAM_MAJOR_VERSION       1
#define PROGRAM_MINOR_VERSION       8
#define PROGRAM_REVISION_NUMBER     4
#define PROGRAM_BUILD_NUMBER        2004

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
#define T_RESCAN                L"Rescan"
#define T_EMPTY                 L" "

#define T_DRIVER_REQUIRED       TEXT("Support from helper driver is required for this feature.\r\n\r\n\
If you see this message it can be caused by:\r\n\
1) Support driver is not loaded or cannot be opened due to insufficient security rights;\r\n\
2) There is a internal error processing request to the heper driver.")

#define T_RICHEDIT_LIB          TEXT("RICHED32.DLL")

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
// Main menu initialization id's
//

// File
#define IDMM_FILE   0

// View
#define IDMM_VIEW   1

// Object
#define IDMM_OBJECT 2

// Find
#define IDMM_FIND   3

// Extras
#define IDMM_EXTRAS 4

// Help
#define IDMM_HELP   5

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
    BOOL IsThreadToken;
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
    HICON ObjectIcon;
    HICON ObjectTypeIcon;
    OBJINFO ObjectInfo; //object dump related structures
    PROP_NAMESPACE_INFO NamespaceInfo;
    PROP_UNNAMED_OBJECT_INFO UnnamedObjectInfo;
} PROP_OBJECT_INFO, *PPROP_OBJECT_INFO;

#define VALIDATE_PROP_CONTEXT(Context) { if (Context == NULL) return; }

//
// If dialog already present - activate it window and return.
//
#define ENSURE_DIALOG_UNIQUE(Dialog) {      \
    if (Dialog != NULL) {                   \
        SetActiveWindow(Dialog);            \
        return;                             \
    }                                       \
}

// If dialog already present - activate/restore it window and return.
#define ENSURE_DIALOG_UNIQUE_WITH_RESTORE(Dialog) {         \
    if (Dialog != NULL) {                                   \
        if (IsIconic(Dialog))                               \
            ShowWindow(Dialog, SW_RESTORE);                 \
        else                                                \
            SetActiveWindow(Dialog);                        \
        return;                                             \
    }                                                       \
}

typedef struct _PROP_DIALOG_CREATE_SETTINGS {
    HWND hwndParent;
    LPWSTR lpObjectName;
    LPCWSTR lpObjectType;
    LPWSTR lpDescription;
    PROP_NAMESPACE_INFO *NamespaceObject;
    PROP_UNNAMED_OBJECT_INFO *UnnamedObject;
} PROP_DIALOG_CREATE_SETTINGS, *PPROP_DIALOG_CREATE_SETTINGS;

typedef struct _VALUE_DESC {
    LPWSTR lpDescription;
    DWORD dwValue;
} VALUE_DESC, *PVALUE_DESC;

//Constants
//Display simple "N/A" if no info available
#define T_CannotQuery	TEXT("N/A")
#define T_NotAssigned   T_CannotQuery

//Value is not defined
#define T_None          TEXT("None")
#define T_NoneValue     TEXT("(None)")

//Value is invalid
#define T_Invalid       TEXT("Invalid")
#define T_InvalidValue  TEXT("(Invalid)")

//Display for unknown type value
#define T_UnknownType	TEXT("Unknown Type")
#define T_UnknownFlag	TEXT("Unknown Flag")

//Display for unknown value
#define T_Unknown		TEXT("Unknown")
#define T_UnknownValue  TEXT("(Unknown)")

//Empty string
#define T_EmptyString   TEXT("")

//prop used by sheets
#define T_PROPCONTEXT	TEXT("propContext")

//prop used by prop dialog
#define T_DLGCONTEXT	TEXT("dlgContext")

//props used by ipc dialogs
#define T_IPCDLGCONTEXT TEXT("IpcDlgContext")

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

#define wobjInitSuccess         0
#define wobjInitNoHeap          -1
#define wobjInitNoTemp          -2
#define wobjInitNoWinDir        -3
#define wobjInitNoSys32Dir      -4
#define wobjInitNoProgDir       -5

#define T_WOBJINIT_NOCRT TEXT("Could not initialize CRT, abort")
#define T_WOBJINIT_NOHEAP TEXT("Could not initialize WinObjEx64, could not allocate heap")
#define T_WOBJINIT_NOTEMP TEXT("Could not initialize WinObjEx64, could not locate %temp%")
#define T_WOBJINIT_NOWINDIR TEXT("Could not initialize WinObjEx64, could not locate Windows directory")
#define T_WOBJINIT_NOSYS32DIR TEXT("Could not initialize WinObjEx64, could not locate System32 directory")
#define T_WOBJINIT_NOPROGDIR TEXT("Could not initialize WinObjEx64, could not query program directory")
#define T_WOBJINIT_NOCLASS TEXT("Could not register WinObjEx64 window class, abort")
#define T_WOBJINIT_NOMAINWINDOW TEXT("Could not create WinObjEx64 main window, abort")
#define T_WOBJINIT_NOICCX TEXT("Could not initialize commctrl classes, abort")
#define T_WOBJINIT_NOLISTWND TEXT("Could not create tree window, abort")
#define T_WOBJINIT_NOTREEWND TEXT("Could not create list window, abort")
#define T_WOBJINIT_NOTLBARWND TEXT("Could not create toolbar window, abort")

#define ErrShadowWin32kNotFound             1
#define ErrShadowMemAllocFail               2
#define ErrShadowWin32uLoadFail             3
#define ErrShadowWin32kLoadFail             4
#define ErrShadowApiSetNotFound             5
#define ErrShadowW32pServiceLimitNotFound   6
#define ErrShadowWin32uMismatch             7
#define ErrShadowW32pServiceTableNotFound   8
#define ErrShadowApiSetSchemaMapNotFound    9
#define ErrShadowApiSetSchemaVerUnknown     10

#define T_ERRSHADOW_WIN32K_NOT_FOUND TEXT("Could not find win32k module")
#define T_ERRSHADOW_MEMORY_NOT_ALLOCATED TEXT("Could not create heap for table")
#define T_ERRSHADOW_WIN32U_LOAD_FAILED TEXT("Could not load win32u.dll")
#define T_ERRSHADOW_WIN32K_LOAD_FAILED TEXT("Could not load win32k.sys")
#define T_ERRSHADOW_APISETTABLE_NOT_FOUND TEXT("Win32kApiSetTable was not found, win32k adapters targets will not be determinated")
#define T_ERRSHADOW_WIN32KLIMIT_NOT_FOUND TEXT("W32pServiceLimit not found in win32k module")
#define T_ERRSHADOW_WIN32U_MISMATCH TEXT("Not all services found in win32u")
#define T_ERRSHADOW_TABLE_NOT_FOUND TEXT("W32pServiceTable not found in win32k module")
#define T_ERRSHADOW_APISETMAP_NOT_FOUND TEXT("ApiSetSchema map not found")
#define T_ERRSHADOW_APISET_VER_UNKNOWN TEXT("ApiSetSchema version is unknown")
