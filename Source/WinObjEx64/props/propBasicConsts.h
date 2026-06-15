/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2026
*
*  TITLE:       PROPBASICCONSTS.H
*
*  VERSION:     2.11
*
*  DATE:        11 Jun 2026
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
static LPCWSTR T_ObjectFlags[] = {
    L"NewObject",
    L"KernelObject",
    L"KernelOnlyAccess",
    L"ExclusiveObject",
    L"PermanentObject",
    L"DefaultSecurityQuota",
    L"SingleHandleEntry",
    L"DeletedInline"
};

//
// Process Trust Label related descriptions.
//
static VALUE_DESC TrustLabelProtectionType[] = {
    { L"None",  0x0 },
    { L"PPL", 0x200 },
    { L"PP", 0x400 }
};

static VALUE_DESC TrustLabelProtectionLevel[] = {
    { L"None",  0x0 },
    { L"Authenticode", 0x400 },
    { L"Antimalware", 0x600 },
    { L"App", 0x800 },
    { L"Windows", 0x1000 },
    { L"WinTcb", 0x2000 }
};

LPCWSTR T_ProcessTypeFlags[] = {
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

static LPWSTR T_PSPROTECTED_SIGNER[] = {
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

static LPWSTR T_PSPROTECTED_TYPE[] = {
    L"None",
    L"ProtectedLight",
    L"Protected"
};

