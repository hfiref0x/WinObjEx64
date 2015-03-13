/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.11
*
*  DATE:        10 Mar 2015
*
*  Common header file for the Windows Object Explorer.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 6102) // Using %s from failed function call at line %u

#include <Windows.h>
#include <commctrl.h>
#include "minirtl\minirtl.h"
#include <ntstatus.h>
#include "ntos.h"
#include "ui.h"
#include "sup.h"
#include "supConsts.h"
#include "list.h"
#include "kldbg.h"
#include "instdrv.h"
#include "excepth.h"
#include "resource.h"

//project global variable
HINSTANCE g_hInstance;
