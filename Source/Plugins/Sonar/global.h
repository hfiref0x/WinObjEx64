/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2020
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.03
*
*  DATE:        30 June 2020
*
*  Common header file for the Windows Object Explorer Sonar plugin.
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
#include <CommCtrl.h>
#include <Uxtheme.h>

#pragma warning(push)
#pragma warning(disable: 4005)
#include <ntstatus.h>
#pragma warning(pop)

#pragma warning(disable: 6320) //Exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER

#include "ntos/ntos.h"
#include "treelist/treelist.h"
#include "minirtl/minirtl.h"
#include "ntos/ntsup.h"
#include "plugin_def.h"
#include "ui.h"
#include "resource.h"
#include "ndis.h"
#include "query.h"

//declared in main.c
extern SONARCONTEXT g_ctx;

#ifdef _DEBUG
#define kdDebugPrint(f, ...) DbgPrint(f, __VA_ARGS__)
#else
#define kdDebugPrint(f, ...) 
#endif
