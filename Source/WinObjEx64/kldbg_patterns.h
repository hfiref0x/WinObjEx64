/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       KLDBG_PATTERNS.H
*
*  VERSION:     1.82
*
*  DATE:        19 Nov 2019
*
*  Header with search patterns used by KLDBG.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// Win32kApiSetTable signatures
//
// 18995
BYTE Win32kApiSetTableMovPattern[] = {
    0x49, 0x8B, 0xFE
};

BYTE Win32kApiSetTableLeaPattern[] = {
    0x4C, 0x8D, 0x2D
};

//
// ObpLookupNamespaceEntry signatures
//

// 7600, 7601, 9600, 10240
BYTE NamespacePattern[] = {
    0x0F, 0xB6, 0x7A, 0x28, 0x48, 0x8D, 0x05
};

// 9200 (8 failed even here)
BYTE NamespacePattern8[] = {
    0x0F, 0xB6, 0x79, 0x28, 0x48, 0x8D, 0x05
};

/*+++

 Host Server Silo signature patterns

+++*/

//
// PrivateNamespaces redesigned in Windows 10 starting from 10586.
//

BYTE PsGetServerSiloGlobalsPattern_14393[] = {
    0x48, 0x83, 0xEC, 0x28, 0x48, 0x83, 0xF9, 0xFF
};

BYTE PsGetServerSiloGlobalsPattern_15064_16299[] = {
    0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0xC1, 0x48, 0x83, 0xF9, 0xFF
};

//
// lea rax, ObpPrivateNamespaceLookupTable
//
BYTE LeaPattern_PNS[] = {
    0x48, 0x8d, 0x05
};

//KiSystemServiceStartPattern(KiSystemServiceRepeat) signature

BYTE  KiSystemServiceStartPattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };

//
// lea r10, KeServiceDescriptorTable
//
BYTE LeaPattern_KeServiceDescriptorTable[] = {
    0x4c, 0x8d, 0x15
};

//
// lea r11, KeServiceDescriptorTableShadow
//
BYTE LeaPattern_KeServiceDescriptorTableShadow[] = {
    0x4c, 0x8d, 0x1d
};
