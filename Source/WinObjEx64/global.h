/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.87
*
*  DATE:        12 July 2020
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
#pragma warning(disable: 4091) // 'typedef ': ignored on left of '%s' when no variable is declared
#pragma warning(disable: 4201) // nameless struct/union
#pragma warning(disable: 6255 6263) // alloca
#pragma warning(disable: 6320) // Exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER.
#pragma warning(disable: 6258) // Using TerminateThread does not allow proper thread clean up.
#pragma warning(disable: 26812) // Prefer 'enum class' over 'enum'
#pragma warning(disable: 26493) // Don't use C style casts

// C++ meaningless warnings
#pragma warning(disable: 26446)
#pragma warning(disable: 26481)
#pragma warning(disable: 26482)
#pragma warning(disable: 26485)
#pragma warning(disable: 26489)
#pragma warning(disable: 26494)

//
// Included lib files used by program.
// Unless it is part of runtime unit (e.g. ntos/treelist) they must be listed here.
//
#pragma comment(lib, "Aclui.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "Setupapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "Version.lib")

#if defined (_MSC_VER)
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

#include "resource.h"
#include "sdk/extdef.h"
#include "wine.h"
#include "minirtl\minirtl.h"
#include "minirtl\rtltypes.h"
#include "ntos\ntos.h"
#include "ntos\ntalpc.h"
#include "ntos\ntsup.h"

#define _NTDEF_
#include <ntsecapi.h>
#undef _NTDEF_

#include "ksymbols.h"
#include "objects.h"
#include "kldbg.h"
#include "drvhelper.h"
#include "ui.h"
#include "sup.h"
#include "supConsts.h"
#include "list.h"
#include "instdrv.h"
#include "excepth.h"
#include "extapi.h"
#include "plugmngr.h"
#include "log\log.h"
#include "tests\testunit.h"

#if defined(__cplusplus)
#include <malloc.h>
#endif

typedef int(__cdecl *pswprintf_s)(
    wchar_t *buffer,
    size_t sizeOfBuffer,
    const wchar_t *format,
    ...);

typedef void(__cdecl *pqsort)(
    _Inout_updates_bytes_(_NumOfElements * _SizeOfElements) void*  _Base,
    _In_ size_t _NumOfElements,
    _In_ size_t _SizeOfElements,
    _In_ int(__cdecl* _PtFuncCompare)(void const*, void const*)
    );

//declared in main.c
extern pswprintf_s rtl_swprintf_s;
extern pqsort rtl_qsort;

#define RtlStringCchPrintfSecure rtl_swprintf_s
#define RtlQuickSort rtl_qsort

typedef struct _WINOBJ_GLOBALS {
    BOOLEAN IsWine;
    BOOLEAN EnableFullMitigations;
    BOOLEAN ListViewDisplayGrid;
    ULONG CurrentDPI;
    HINSTANCE hInstance;
    HANDLE Heap;
    LPWSTR CurrentObjectPath;
    pfnHtmlHelpW HtmlHelpW;
    CRITICAL_SECTION Lock;
    RTL_OSVERSIONINFOW osver;
    HWND AuxDialogs[wobjMaxDlgId];
    WCHAR szTempDirectory[MAX_PATH + 1]; //not including backslash
    WCHAR szWindowsDirectory[MAX_PATH + 1]; //not including backslash
    WCHAR szSystemDirectory[MAX_PATH + 1]; //not including backslash
    WCHAR szProgramDirectory[MAX_PATH + 1]; //not including backslash
} WINOBJ_GLOBALS, *PWINOBJ_GLOBALS;

extern WINOBJ_GLOBALS g_WinObj;
