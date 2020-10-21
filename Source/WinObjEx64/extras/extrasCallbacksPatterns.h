/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2020
*
*  TITLE:       EXTRASCALLBACKSPATTERNS.H
*
*  VERSION:     1.87
*
*  DATE:        20 Oct 2020
*
*  Header with search patterns used by Callbacks dialog routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// PsAltSystemCallHandlers
//
#define MAX_ALT_SYSTEM_CALL_HANDLERS 2

BYTE PsAltSystemCallHandlersPattern[] = {
    0x4C, 0x8D, 0x35
};


/*+++

 SeCiCallbacks search patterns

+++*/

//Windows 8/8.1
BYTE SeCiCallbacksPattern_9200_9600[] = { 0x48, 0x83, 0xEC, 0x20, 0xBF, 0x06, 0x00, 0x00, 0x00 };

//Windows 10 TH1/TH2
BYTE SeCiCallbacksPattern_10240_10586[] = { 0x48, 0x83, 0xEC, 0x20, 0xBB, 0x98, 0x00, 0x00, 0x00 };

//Windows 10 RS1
BYTE SeCiCallbacksPattern_14393[] = { 0x48, 0x83, 0xEC, 0x20, 0xBB, 0xB0, 0x00, 0x00, 0x00 };

//Windows 10 RS2/RS3
BYTE SeCiCallbacksPattern_15063_16299[] = { 0x48, 0x83, 0xEC, 0x20, 0xBB, 0xC0, 0x00, 0x00, 0x00 };

//Windows 10 RS4/RS5
BYTE SeCiCallbacksPattern_17134_17763[] = { 0x48, 0x83, 0xEC, 0x20, 0xBB, 0xD0, 0x00, 0x00, 0x00 };

//
// Windows 19H1/19H2/20H1/20H2
//
// Locate SepInitializeCodeIntegrity pattern.
// These are params for memset.
//

BYTE SeCiCallbacksPattern_19H1_20H2[] = { 0x41, 0xB8, 0xC4, 0x00, 0x00, 0x00, 0xBF, 0x06, 0x00, 0x00, 0x00 };

// Instruction match pattern
BYTE SeCiCallbacksMatchingPattern[] = { 0x48, 0x8D, 0x0D };
BYTE SeCiCallbacksMatchingPattern_19H1_20H2[] = { 0xC7, 0x05 };

//Windows 7
BYTE g_CiCallbacksPattern_7601[] = { 0x8D, 0x7B, 0x06, 0x48, 0x89, 0x05 };
BYTE g_CiCallbacksMatchingPattern[] = { 0x48, 0x89, 0x05 };
