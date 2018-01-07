/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.52
*
*  DATE:        08 Jan 2018
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
#pragma warning(disable: 6102) // Using %s from failed function call at line %u
#if (_MSC_VER >= 1900)
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
#if (_MSC_VER >= 1900)
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif

#include <Windows.h>
#include <commctrl.h>
#include <ntstatus.h>
#include <sddl.h>
#include "minirtl\minirtl.h"
#include "minirtl\rtltypes.h"
#include "ntos\ntos.h"
#include "ntos\ntalpc.h"
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

typedef struct _WINOBJ_GLOBALS {
    HINSTANCE hInstance;
    HANDLE Heap;
    HANDLE hNtdllModule;
    LPWSTR CurrentObjectPath;
    pfnHtmlHelpW HtmlHelpW;
    HWND AuxDialogs[WOBJ_MAX_DIALOGS];
    CRITICAL_SECTION Lock;
    RTL_OSVERSIONINFOW osver;
    WCHAR szTempDirectory[MAX_PATH + 1]; //not including backslash
    WCHAR szWindowsDirectory[MAX_PATH + 1]; //not including backslash
    WCHAR szSystemDirectory[MAX_PATH + 1]; //not including backslash
} WINOBJ_GLOBALS, *PWINOBJ_GLOBALS;

WINOBJ_GLOBALS g_WinObj;
