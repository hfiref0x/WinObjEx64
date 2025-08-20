/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2024
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     2.05
*
*  DATE:        05 Jun 2024
*
*  Common header file for the Windows Object Explorer.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

//
// Strict UNICODE
//
#if !defined UNICODE
#error ANSI build is not supported
#endif

//
// Ignored warnings
//
#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4054) // 'type cast': from function pointer '%' to data pointer '%'
#pragma warning(disable: 4055) // 'type cast': from data pointer '%' to function pointer '%'
#pragma warning(disable: 4091) // 'typedef ': ignored on left of '%s' when no variable is declared
#pragma warning(disable: 4201) // nameless struct/union
#pragma warning(disable: 4390) // empty controlled statement
#pragma warning(disable: 5105) // macro expansion producing 'defined' has undefined behavior
#pragma warning(disable: 6320) // Exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER.
#pragma warning(disable: 6258) // Using TerminateThread does not allow proper thread clean up.

// C++ meaningless warnings
#pragma warning(disable: 26446)
#pragma warning(disable: 26481)
#pragma warning(disable: 26482)
#pragma warning(disable: 26485)
#pragma warning(disable: 26489)
#pragma warning(disable: 26493) // Don't use C style casts
#pragma warning(disable: 26494)
#pragma warning(disable: 26812) // Prefer 'enum class' over 'enum'

//
// Included lib files used by program.
// Unless it is part of runtime unit (e.g. ntos/treelist) they must be listed here.
//
#pragma comment(lib, "Aclui.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "Setupapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "Version.lib")

#if defined (_MSC_VER) //for vs2015
#if (_MSC_VER <= 1900)
#pragma warning(disable: 4214)
#pragma warning(disable: 4204)
#endif
#if (_MSC_VER >= 1900)
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libucrt.lib")
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif
#endif

#if defined (_MSC_VER)
#if (_MSC_VER >= 1920)
#pragma comment(linker,"/merge:_RDATA=.rdata")
#endif
#endif

#include <Windows.h>
#include <Windowsx.h>
#include <commctrl.h>
#include <Uxtheme.h>
#include <ShlObj.h>
#include <ntstatus.h>
#include <sddl.h>
#include <slpublic.h>
#include <cfgmgr32.h>
#include <setupapi.h>
#include <shlwapi.h>
#include <Richedit.h>
#include <Aclui.h>
#include <Aclapi.h>
#include <FltUser.h>
#include <assert.h>

#include "resource.h"
#include "sdk/extdef.h"

#include "minirtl/minirtl.h"
#include "minirtl/rtltypes.h"
#include "minirtl/_filename.h"

#include "ntos/ntos.h"
#include "ntos/ntalpc.h"
#include "ntos/ntsup.h"
#include "ntos/ntbuilds.h"
#include "ntuser/ntuser.h"

#define _NTDEF_
#include <ntsecapi.h>
#undef _NTDEF_

#include "symparser.h"
#include "objects.h"
#include "drivers/wdrvprv.h"
#include "log/log.h"
#include "kldbg.h"
#include "propCommon.h"
#include "ui.h"
#include "sup/sup.h"
#include "sup/wine.h"
#include "hash.h"
#include "extapi.h"
#include "list.h"
#include "excepth.h"
#include "plugmngr.h"
#include "tests/testunit.h"

#if defined(__cplusplus)
#include <malloc.h>
#endif

_Success_(return >= 0)
typedef int(__cdecl *pswprintf_s)(
    _Out_writes_opt_(sizeOfBuffer) _Always_(_Post_z_) wchar_t *buffer,
    _In_ size_t sizeOfBuffer,
    _In_z_ _Printf_format_string_params_(1) const wchar_t *format,
    ...);

typedef void(__cdecl *pqsort)(
    _Inout_updates_bytes_(_NumOfElements * _SizeOfElements) void*  _Base,
    _In_ size_t _NumOfElements,
    _In_ size_t _SizeOfElements,
    _In_ int(__cdecl* _PtFuncCompare)(void const*, void const*)
    );

//declared in main.c
extern pswprintf_s _swprintf_s;
extern pqsort _qsort;

#define RtlStringCchPrintfSecure _swprintf_s
#define RtlQuickSort _qsort

typedef struct _WINOBJ_STATS {
    ULONG TotalHeapAlloc;
    ULONG TotalHeapFree;
    ULONG TotalHeapsCreated;
    ULONG TotalHeapsDestroyed;
    ULONG TotalThreadsCreated;
    ULONG64 TotalHeapMemoryAllocated;
#ifdef _DEBUG
    ULONG64 MaxHeapAllocatedBlockSize;
#endif
} WINOBJ_STATS, *PWINOBJ_STATS;

extern WINOBJ_STATS g_WinObjStats;

#define OBEX_STATS_INC(Name) (InterlockedIncrement((LONG*)&g_WinObjStats.Name))
#define OBEX_STATS_INC64(Name, Value) (InterlockedAdd64((LONG64*)&g_WinObjStats.Name, Value))

typedef struct _WINOBJ_GLOBALS {
    BOOLEAN IsWine;
    BOOLEAN ListViewDisplayGrid;

    ATOM MainWindowClassAtom;
    ATOM TreeListAtom;

    HIMAGELIST ToolBarMenuImages;
    HIMAGELIST ListViewImages;

    HWND MainWindow;
    HWND MainWindowStatusBar;
    HWND MainWindowToolBar;
    HWND MainWindowSplitter;

    HWND ObjectListView;
    HWND ObjectTreeView;

    UINT SettingsChangeMessage;
    ULONG CurrentDPI;
    HINSTANCE hInstance;
    HANDLE Heap;
    
    LIST_ENTRY ObjectPathListHead;

    pfnHtmlHelpW HtmlHelpW;
    RTL_OSVERSIONINFOW osver;

    WCHAR szTempDirectory[MAX_PATH + 1]; //not including backslash
    WCHAR szWindowsDirectory[MAX_PATH + 1]; //not including backslash
    WCHAR szSystemDirectory[MAX_PATH + 1]; //not including backslash
    WCHAR szProgramDirectory[MAX_PATH + 1]; //not including backslash
} WINOBJ_GLOBALS, *PWINOBJ_GLOBALS;

extern WINOBJ_GLOBALS g_WinObj;

//
// Shared heap
//
#define g_obexHeap g_WinObj.Heap

//
// Current object path list
//
#define g_ObjectPathListHead g_WinObj.ObjectPathListHead

#define g_ListViewImages g_WinObj.ListViewImages
#define g_ToolBarMenuImages g_WinObj.ToolBarMenuImages
#define g_hwndObjectList g_WinObj.ObjectListView
#define g_hwndObjectTree g_WinObj.ObjectTreeView

//
// Main program window
//
#define g_hwndMain g_WinObj.MainWindow

#define g_hwndStatusBar g_WinObj.MainWindowStatusBar
#define g_hwndToolBar g_WinObj.MainWindowToolBar
#define g_hwndSplitter g_WinObj.MainWindowSplitter

