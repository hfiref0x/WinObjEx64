/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019
*
*  TITLE:       PROPBASICCONSTS.H
*
*  VERSION:     1.72
*
*  DATE:        04 Feb 2019
*
*  Consts header file for Basic property sheet.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

//OBJECT_HEADER Flags
LPCWSTR T_ObjectFlags[8] = {
    L"NewObject",
    L"KernelObject",
    L"KernelOnlyAccess",
    L"Exclusive",
    L"Permanent",
    L"DefSecurityQuota",
    L"SingleHandleEntry",
    L"DeletedInline"
};

//
// Process Trust Label related descriptions.
//

#define MAX_KNOWN_TRUSTLABEL_PROTECTIONTYPE 3
static VALUE_DESC TrustLabelProtectionType[MAX_KNOWN_TRUSTLABEL_PROTECTIONTYPE] = {
    { L"None",  0x0 },
    { L"ProtectedLight", 0x200 },
    { L"Protected", 0x400 }
};

#define MAX_KNOWN_TRUSTLABEL_PROTECTIONLEVEL 6
static VALUE_DESC TrustLabelProtectionLevel[MAX_KNOWN_TRUSTLABEL_PROTECTIONLEVEL] = {
    { L"None",  0x0 },
    { L"Authenticode", 0x400 },
    { L"Antimalware", 0x600 },
    { L"App", 0x800 },
    { L"Windows", 0x1000 },
    { L"WinTcb", 0x2000 }
};
