/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2017
*
*  TITLE:       PROPDRIVERCONSTS.H
*
*  VERSION:     1.46
*
*  DATE:        07 Mar 2017
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
#define PROPDRVREGSERVICESKEY     L"\\HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\%ws"
#define PROPDRVREGSERVICESKEYLEN  sizeof(REGISTRYSERVICESKEY) - sizeof(WCHAR)
