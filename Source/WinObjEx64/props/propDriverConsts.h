/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       PROPDRIVERCONSTS.H
*
*  VERSION:     1.52
*
*  DATE:        08 Jan 2018
*
*  Common header file for Driver property sheet.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define REGEDITWNDCLASS           L"RegEdit_RegEdit"
#define REGEDIT_EXE               L"regedit.exe"
#define SHELL_OPEN_VERB           L"open"

//
// Path to navigate in the regedit window treeview.
//
#define PROPDRVREGSERVICESKEY     L"\\HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\"
#define PROPDRVREGSERVICESKEYLEN  sizeof(PROPDRVREGSERVICESKEY) - sizeof(WCHAR)
