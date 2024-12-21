/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2024
*
*  TITLE:       UI.H
*
*  VERSION:     2.06
*
*  DATE:        21 Dec 2024
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

#define SplitterSize                3
#define SplitterMargin              80

#define DefaultSystemDpi            96

#define SCALE_DPI_VALUE(Value, CurrentDPI) MulDiv(Value, CurrentDPI, DefaultSystemDpi)

#define TreeListDumpObjWndPosX      12
#define TreeListDumpObjWndPosY      20
#define TreeListDumpObjWndScaleSub  3


//
// Main ListView column count
//
#define MAIN_OBJLIST_COLUMN_COUNT 3

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

#define PROGRAM_MAJOR_VERSION       2
#define PROGRAM_MINOR_VERSION       0
#define PROGRAM_REVISION_NUMBER     6
#define PROGRAM_BUILD_NUMBER        2412

#ifdef _USE_OWN_DRIVER
#define PROGRAM_NAME            L"Windows Object Explorer 64-bit (Non-public version)"
#else 
#define PROGRAM_NAME            L"Windows Object Explorer 64-bit"
#endif
#define PROFRAM_NAME_AND_TITLE  L"Object Explorer for Windows 7/8/8.1/10/11"
#define WINOBJEX64_WNDCLASS     L"WinObjEx64Class"
#define WINOBJEX64_PSLISTCLASS  L"WinObjEx64PsListClass"

#define T_COPY_OBJECT_NAME      L"Copy Name"
#define T_COPY_OBJECT_NAME_BIN  L"Copy Name (Binary)"

#define T_PROPERTIES            L"Properties...\tEnter"
#define T_GOTOLINKTARGET        L"Go To Link Target\tCtrl+->"
#define T_VIEWSD                L"View Security Descriptor..."
#define T_RUNASADMIN            L"R&un as Administrator"
#define T_RUNASSYSTEM           L"R&un as LocalSystem"
#define T_EXPORTTOFILE          L"Export List"
#define T_JUMPTOFILE            L"Jump to File"
#define T_VIEW_REFRESH          L"Refresh\tF5"
#define T_VIEW_PLUGINS          L"View Plugins"
#define T_EMPTY                 L" "
#define T_MSG_SETTINGS_CHANGE   L"wobjSettingsChange"

#define T_CSV_FILE_FILTER       TEXT("CSV Files\0*.csv\0\0")
#define T_LIST_EXPORT_SUCCESS   TEXT("List export - OK")
#define T_RICHEDIT_LIB          TEXT("RICHED32.DLL")

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

typedef struct _TL_SUBITEMS_FIXED {
    ULONG       Count;
    ULONG       ColorFlags;
    COLORREF    BgColor;
    COLORREF    FontColor;
    PVOID       UserParam;
    LPTSTR      CustomTooltip;
    LPTSTR      Text[2];
} TL_SUBITEMS_FIXED, *PTL_SUBITEMS_FIXED;

typedef struct _VALUE_DESC {
    LPWSTR lpDescription;
    DWORD dwValue;
} VALUE_DESC, *PVALUE_DESC;

typedef struct _LVCOLUMNS_DATA {
    LPWSTR Name;
    INT Width;
    INT Format;
    INT ImageIndex;
} LVCOLUMNS_DATA, *PLVCOLUMNS_DATA;

//
// Constants
//
// 
// Display simple "N/A" if no info available
#define T_CannotQuery       TEXT("N/A")
#define T_NotAssigned       T_CannotQuery

// Value is not defined
#define T_None              TEXT("None")
#define T_NoneValue         TEXT("(None)")

// Value is invalid
#define T_Invalid           TEXT("Invalid")
#define T_InvalidValue      TEXT("(Invalid)")

// Display for unknown type value
#define T_UnknownType       TEXT("Unknown Type")

// Display for unknown flag value
#define T_UnknownFlag       TEXT("Unknown Flag")

// Display for unknown process
#define T_UnknownProcess    TEXT("Unknown Process")

// Display for unknown value
#define T_Unknown           TEXT("Unknown")

// Empty string
#define T_EmptyString       TEXT("")

// prop used by sheets
#define T_PROPCONTEXT       TEXT("propContext")

// prop used by prop dialog
#define T_DLGCONTEXT        TEXT("dlgContext")

// prop used by ipc dialogs
#define T_IPCDLGCONTEXT     TEXT("IpcDlgContext")

#define INIT_NO_ERROR               0
#define INIT_ERROR_NOCRT            1
#define INIT_ERROR_NOHEAP           2
#define INIT_ERROR_NOTEMP           3
#define INIT_ERROR_NOWINDIR         4
#define INIT_ERROR_NOSYS32DIR       5
#define INIT_ERROR_NOPROGDIR        6
#define INIT_ERROR_NOCLASS          7
#define INIT_ERROR_NOMAINWND        8
#define INIT_ERROR_NOICCX           9
#define INIT_ERROR_NOLISTWND        10
#define INIT_ERROR_NOTREEWND        11
#define INIT_ERROR_NOTLBARWND       12
#define INIT_ERROR_NOSPLITTERWND    13
#define INIT_ERROR_UNSPECIFIED      14

#define T_WOBJINIT_NOCRT TEXT("Could not initialize CRT, abort")

#define ErrShadowWin32kNotFound             1
#define ErrShadowMemAllocFail               2
#define ErrShadowWin32uLoadFail             3
#define ErrShadowWin32kLoadFail             4
#define ErrShadowApiSetNotFound             5
#define ErrShadowW32pServiceLimitNotFound   6
#define ErrShadowWin32uMismatch             7
#define ErrShadowW32pServiceTableNotFound   8
#define ErrShadowApiSetSchemaVerUnknown     9
#define ErrShadowWin32kGlobalsNotFound      10
#define ErrShadowWin32kOffsetNotFound       11
#define ErrShadowWin32kGetStateNotFound     12

//
// Common Dialog handlers.
//
VOID FindDlgCreate(
    VOID);

VOID ShowSysInfoDialog(
    _In_ HWND hwndParent);

VOID SDViewDialogCreate(
    _In_ WOBJ_OBJECT_TYPE ObjectType);

INT_PTR CALLBACK AboutDialogProc(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam);

VOID ShowStatsDialog(
    VOID);
