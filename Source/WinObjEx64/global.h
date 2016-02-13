/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2016
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.40
*
*  DATE:        13 Feb 2016
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

#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 6102) // Using %s from failed function call at line %u

#if !defined UNICODE
#error ANSI build is not supported
#endif

#if (_MSC_VER >= 1900)
#pragma warning(disable: 4091) // 'typedef ': ignored on left of '' when no variable is declared
#pragma warning(disable: 4311) // 'type cast': pointer truncation from %s to %s
#pragma warning(disable: 4312) // 'type cast': conversion from %s to %s of greater size
#endif

#include <Windows.h>
#include <commctrl.h>
#include "minirtl\minirtl.h"
#include <ntstatus.h>
#include "ntos.h"
#include "kldbg.h"
#include "ldr\ldr.h"
#include "ui.h"
#include "sup.h"
#include "supConsts.h"
#include "list.h"
#include "instdrv.h"
#include "excepth.h"
#include "resource.h"

//project global variable
HINSTANCE g_hInstance;
