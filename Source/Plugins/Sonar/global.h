/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.00
*
*  DATE:        10 Aug 2019
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
#include "plugin_def.h"
#include "ui.h"
#include "resource.h"
#include "ndis.h"
#include "query.h"

extern SONARCONTEXT g_ctx;
