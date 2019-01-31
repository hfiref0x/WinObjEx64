/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.71
*
*  DATE:        31 Jan 2019
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
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 4302) // 'type cast': truncation from '%s' to '%s'
#pragma warning(disable: 6102) // Using %s from failed function call at line %u
#pragma warning(disable: 6255 6263) // alloca
#pragma warning(disable: 6320) // Exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER. This might mask exceptions that were not intended to be handled.
#if (_MSC_VER >= 1900)
#pragma warning(disable: 4054) // 'type cast': from function pointer %s to data pointer %s
#pragma warning(disable: 4091) // 'typedef ': ignored on left of '' when no variable is declared
#pragma warning(disable: 4311) // 'type cast': pointer truncation from %s to %s
#pragma warning(disable: 4312) // 'type cast': conversion from %s to %s of greater size
#endif


//
// Included lib files used by program.
// Unless it is part of runtime unit (e.g. ntos/treelist) they must be listed here.
//
#pragma comment(lib, "Aclui.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "Setupapi.lib")
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
#include <commctrl.h>
#include <Uxtheme.h>
#include <ntstatus.h>
#include "wine.h"
#include <sddl.h>
#include "minirtl\minirtl.h"
#include "minirtl\rtltypes.h"
#include "ntos\ntos.h"
#include "ntos\ntalpc.h"

#define _NTDEF_
#include <ntsecapi.h>
#undef _NTDEF_

#include "objects.h"
#include "kldbg.h"
#include "ui.h"
#include "sup.h"
#include "supConsts.h"
#include "list.h"
#include "instdrv.h"
#include "excepth.h"
#include "extapi.h"
#include "tests\testunit.h"
#include "resource.h"

#if defined(__cplusplus)
#include <malloc.h>
#endif

typedef struct _WINOBJ_GLOBALS {
    BOOL EnableExperimentalFeatures;
    HINSTANCE hInstance;
    HANDLE Heap;
    LPWSTR CurrentObjectPath;
    pfnHtmlHelpW HtmlHelpW;
    HWND AuxDialogs[wobjMaxDlgId];
    CRITICAL_SECTION Lock;
    RTL_OSVERSIONINFOW osver;
    WCHAR szTempDirectory[MAX_PATH + 1]; //not including backslash
    WCHAR szWindowsDirectory[MAX_PATH + 1]; //not including backslash
    WCHAR szSystemDirectory[MAX_PATH + 1]; //not including backslash
} WINOBJ_GLOBALS, *PWINOBJ_GLOBALS;

extern WINOBJ_GLOBALS g_WinObj;
