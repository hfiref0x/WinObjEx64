/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2021
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.11
*
*  DATE:        01 June 2021
*
*  Common header file for the Windows Object Explorer ApiSetView plugin.
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

#define OEMRESOURCE
#include <Windows.h>
#include <windowsx.h>
#include <strsafe.h>
#include <commctrl.h>
#include <commdlg.h>
#include <Uxtheme.h>

#pragma warning(push)
#pragma warning(disable: 4005)
#include <ntstatus.h>
#pragma warning(pop)

#pragma warning(disable: 6258) // TerminateThread
#pragma warning(disable: 6320) // Exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER
#pragma warning(disable: 26812) // Prefer 'enum class' over 'enum'


#include "ntos/ntos.h"
#include "ntos/apisetx.h"
#include "treelist/treelist.h"
#include "minirtl/minirtl.h"
#include "plugin_def.h"
#include "resource.h"
#include "ui.h"
#include "query.h"

//
// Declared in main.c
//
extern GUI_CONTEXT g_ctx;
