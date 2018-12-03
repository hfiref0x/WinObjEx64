/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       EXTRASPSLIST.H
*
*  VERSION:     1.70
*
*  DATE:        30 Nov 2018
*
*  Common header file for Process List dialog.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define MAX_KNOWN_PEXBI_PROCESS_FLAGS 9
static LPWSTR T_PEXBI_PROCESS_FLAGS[MAX_KNOWN_PEXBI_PROCESS_FLAGS] = {
    L"IsProtectedProcess",
    L"IsWow64Process",
    L"IsProcessDeleting",
    L"IsCrossSessionCreate",
    L"IsFrozen",
    L"IsBackground",
    L"IsStronglyNamed",
    L"IsSecureProcess",
    L"IsSubsystemProcess"
};

#define MAX_KNOWN_PS_PROTECTED_SIGNER 9
static LPWSTR T_PSPROTECTED_SIGNER[MAX_KNOWN_PS_PROTECTED_SIGNER] = {
    L"PsProtectedSignerNone",
    L"PsProtectedSignerAuthenticode",
    L"PsProtectedSignerCodeGen",
    L"PsProtectedSignerAntimalware",
    L"PsProtectedSignerLsa",
    L"PsProtectedSignerWindows",
    L"PsProtectedSignerWinTcb",
    L"PsProtectedSignerWinSystem",
    L"PsProtectedSignerApp"
};

#define MAX_KNOWN_PS_PROTECTED_TYPE 3
static LPWSTR T_PSPROTECTED_TYPE[MAX_KNOWN_PS_PROTECTED_TYPE] = {
    L"PsProtectedTypeNone",
    L"PsProtectedTypeProtectedLight",
    L"PsProtectedTypeProtected"
};

VOID extrasCreatePsListDialog(
    _In_ HWND hwndParent);
