/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       KLDBG_PATTERNS.H
*
*  VERSION:     1.71
*
*  DATE:        19 Jan 2019
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

/*+++

 SeCiCallbacks search patterns

+++*/

//Windows 10 TH1/TH2
BYTE SeCiCallbacksPattern_10240_10586[] = { 0x48, 0x83, 0xEC, 0x20, 0xBB, 0x98, 0x00, 0x00, 0x00 };

//Windows 10 RS1
BYTE SeCiCallbacksPattern_14393[] = { 0x48, 0x83, 0xEC, 0x20, 0xBB, 0xB0, 0x00, 0x00, 0x00 };

//Windows 10 RS2/RS3
BYTE SeCiCallbacksPattern_15063_16299[] = { 0x48, 0x83, 0xEC, 0x20, 0xBB, 0xC0, 0x00, 0x00, 0x00 };

//Windows 10 RS4/RS5
BYTE SeCiCallbacksPattern_17134_17763[] = { 0x48, 0x83, 0xEC, 0x20, 0xBB, 0xD0, 0x00, 0x00, 0x00 };

//Windows 8/8.1
BYTE SeCiCallbacksPattern_9200_9600[] = { 0x48, 0x83, 0xEC, 0x20, 0xBF, 0x06, 0x00, 0x00, 0x00 };

BYTE SeCiCallbacksMatchingPattern[] = { 0x48, 0x8D, 0x0D };

//Windows 7
BYTE g_CiCallbacksPattern_7601[] = { 0x8D, 0x7B, 0x06, 0x48, 0x89, 0x05 };
BYTE g_CiCallbacksMatchingPattern[] = { 0x48, 0x89, 0x05 };
