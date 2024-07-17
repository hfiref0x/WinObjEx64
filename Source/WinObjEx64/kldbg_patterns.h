/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2024
*
*  TITLE:       KLDBG_PATTERNS.H
*
*  VERSION:     2.05
*
*  DATE:        11 Jul 2024
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

// lea rax, PspHostSiloGlobals
#define IL_PspHostSiloGlobals                   7

// Number of bytes to scan for table lookup var 1
#define DA_ScanBytesPNSVariant1                 64

// Number of bytes to scan for table lookup var 2
#define DA_ScanBytesPNSVariant2                 128

//  movzx   ecx, byte ptr cs:ObHeaderCookie
#define IL_ObHeaderCookie                       7

// Number of bytes to scan
#define DA_ScanBytesObHeaderCookie              256

//
// ObHeaderCookie
//
BYTE ObHeaderCookiePattern[] = {
    0x0F, 0xB6, 0x0D
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

// lea
#define IL_KeServiceDescriptorTableShadow               7

// Number of bytes to scan
#define DA_ScanBytesKeServiceDescriptorTableShadow      128

//
// KSE
//

#define IL_KseEngine 6
#define DA_ScanBytesKseEngine 64

BYTE KseEnginePattern[] = {
    0x8B, 0x05
};

//
// PAGE: MiRememberUnloadedDriver
//
// mov reg, 7D0h ;  -> NumberOfBytes = MI_UNLOADED_DRIVERS * sizeof (UNLOADED_DRIVERS);
//
BYTE MiRememberUnloadedDriverPattern[] = {
    0xBB, 0xD0, 0x07, 0x00, 0x00
};

//
// PAGE: MiRememberUnloadedDriver
//
// mov reg, 7D0h ;  -> NumberOfBytes = MI_UNLOADED_DRIVERS * sizeof (UNLOADED_DRIVERS);
// mov ecx, 40h  ;
//
BYTE MiRememberUnloadedDriverPattern2[] = {
   0xBA, 0xD0, 0x07, 0x00, 0x00,  // mov     edx, 7D0h
   0xB9, 0x40, 0x00, 0x00, 0x00   // mov     ecx, 40h
};

#define FIX_WIN10_THRESHOULD_REG 0xBF

BYTE MiRememberUnloadedDriverPattern24H2[] = {
    0xBA, 0xD0, 0x07, 0x00, 0x00,  // mov    edx, 7D0h
    0x41, 0x8D, 0x4E, 0x40         // lea    ecx, [r14+40h]
};
