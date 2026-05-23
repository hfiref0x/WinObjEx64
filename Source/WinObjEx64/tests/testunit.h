/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2026
*
*  TITLE:       TESTUNIT.H
*
*  VERSION:     2.11
*
*  DATE:        22 May 2026
*
*  Common header file for test code.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#include "uitest.h"

VOID TestStart(VOID);
VOID TestStop(VOID);
VOID TestException(_In_ BOOL bNaked);
HANDLE TestGetPortHandle();

#ifdef _DEBUG
#define BeginTests() TestStart()
#define EndTests() TestStop()
#define BeginUITests() TestUI()
#else
#define BeginTests()
#define EndTests()
#define BeginUITests()
#endif
