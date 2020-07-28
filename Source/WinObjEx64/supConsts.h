/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       SUPCONSTS.H
*
*  VERSION:     1.87
*
*  DATE:        25 July 2020
*
*  Consts header file for support unit.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define T_SECUREBOOTSTATEKEY        L"System\\CurrentControlSet\\Control\\SecureBoot\\State"
#define T_SECUREBOOTSTATEVALUE      L"UEFISecureBootEnabled"

#define T_VERSION_TRANSLATION       L"\\VarFileInfo\\Translation"
#define FORMAT_VERSION_DESCRIPTION  L"\\StringFileInfo\\%04x%04x\\FileDescription"
#define HHCTRLOCXKEY                L"CLSID\\{ADB880A6-D8FF-11CF-9377-00AA003B7A11}\\InprocServer32"
#define T_OBJECTTYPES               L"\\ObjectTypes"

#define FORMAT_TIME_DATE_VALUE      L"%02hd:%02hd:%02hd, %02hd %ws %04hd"
#define FORMAT_TIME_VALUE           L"%I64u:%02hd:%02hd"
#define FORMAT_TIME_VALUE_MS        L"%hd:%02hd:%02hd.%03hd"
#define T_FORMATTED_ATTRIBUTE       L"           0x"

#define HHCTRLOCX                   L"hhctrl.ocx"

#define T_WINSTA_SYSTEM L"-0x0-3e7$"
#define T_WINSTA_ANONYMOUS L"-0x0-3e6$"
#define T_WINSTA_LOCALSERVICE L"-0x0-3e5$"
#define T_WINSTA_NETWORK_SERVICE L"-0x0-3e4$"

#define supServicesRegPath          L"System\\CurrentControlSet\\Services\\"
#define supServicesRegPathSize      sizeof(supServicesRegPath) - sizeof(WCHAR)

#define MAX_KNOWN_WINSTA_DESCRIPTIONS 4
static WINSTA_DESC g_WinstaDescArray[MAX_KNOWN_WINSTA_DESCRIPTIONS] = {
    { T_WINSTA_SYSTEM, L"System" },
    { T_WINSTA_ANONYMOUS, L"Anonymous" },
    { T_WINSTA_LOCALSERVICE, L"Local Service" },
    { T_WINSTA_NETWORK_SERVICE, L"Network Service" }
};
