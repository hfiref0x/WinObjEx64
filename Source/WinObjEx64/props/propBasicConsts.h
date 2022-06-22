/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2022
*
*  TITLE:       PROPBASICCONSTS.H
*
*  VERSION:     2.00
*
*  DATE:        19 Jun 2022
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

#define T_COULD_NOT_QUERY TEXT("*Could not query requested information*")

//OBJECT_HEADER Flags
static LPCWSTR T_ObjectFlags[8] = {
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
    { L"PPL", 0x200 },
    { L"PP", 0x400 }
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

#define MAX_KNOWN_PROCESS_TYPE_FLAGS 9
LPCWSTR T_ProcessTypeFlags[MAX_KNOWN_PROCESS_TYPE_FLAGS] = {
    L"ProtectedProcess",
    L"Wow64Process",
    L"ProcessDeleting",
    L"CrossSessionCreate",
    L"Frozen",
    L"Background",
    L"StronglyNamed",
    L"SecureProcess",
    L"SubsystemProcess"
};

#define MAX_KNOWN_PS_PROTECTED_SIGNER 9
static LPWSTR T_PSPROTECTED_SIGNER[MAX_KNOWN_PS_PROTECTED_SIGNER] = {
    L"None",
    L"Authenticode",
    L"CodeGen",
    L"Antimalware",
    L"Lsa",
    L"Windows",
    L"WinTcb",
    L"WinSystem",
    L"App"
};

#define MAX_KNOWN_PS_PROTECTED_TYPE 3
static LPWSTR T_PSPROTECTED_TYPE[MAX_KNOWN_PS_PROTECTED_TYPE] = {
    L"None",
    L"ProtectedLight",
    L"Protected"
};

