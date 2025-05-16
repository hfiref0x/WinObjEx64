/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2025
*
*  TITLE:       EXTRASCALLBACKSPATTERNS.H
*
*  VERSION:     2.07
*
*  DATE:        14 May 2025
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
BYTE SeCiCallbacksPattern_9200_9600[] = {
    0x48, 0x83, 0xEC, 0x20, 0xBF, 0x06, 0x00, 0x00, 0x00
};

//Windows 10 TH1/TH2
BYTE SeCiCallbacksPattern_10240_10586[] = {
    0x48, 0x83, 0xEC, 0x20, 0xBB, 0x98, 0x00, 0x00, 0x00
};

//Windows 10 RS1
BYTE SeCiCallbacksPattern_14393[] = {
    0x48, 0x83, 0xEC, 0x20, 0xBB, 0xB0, 0x00, 0x00, 0x00
};

//Windows 10 RS2/RS3
BYTE SeCiCallbacksPattern_15063_16299[] = {
    0x48, 0x83, 0xEC, 0x20, 0xBB, 0xC0, 0x00, 0x00, 0x00
};

//Windows 10 RS4/RS5
BYTE SeCiCallbacksPattern_17134_17763[] = {
    0x48, 0x83, 0xEC, 0x20, 0xBB, 0xD0, 0x00, 0x00, 0x00
};

// Instruction match pattern
BYTE SeCiCallbacksMatchingPattern[] = {
    0x48, 0x8D, 0x0D
};

//Windows 7
BYTE g_CiCallbacksPattern_7601[] = {
    0x8D, 0x7B, 0x06, 0x48, 0x89, 0x05
};

BYTE g_CiCallbacksMatchingPattern[] = {
    0x48, 0x89, 0x05
};

#define LEA_INSTRUCTION_LENGTH_7B 7
#define CI_CALLBACKS_3BYTE_INSTRUCTION_SIZE 3

/*+++

 EmpSearchCallbackDatabase search pattern

+++*/
BYTE g_EmpSearchCallbackDatabase[] = { 0x48, 0x8B, 0x4E, 0xF8, 0x48, 0x85, 0xC9 };
BYTE g_EmpSearchCallbackDatabase2[] = { 0x49, 0x8B, 0x4A, 0xF8, 0x48, 0x85, 0xC9 };
BYTE g_EmpSearchCallbackDatabase3[] = { 0x4B, 0x8B, 0x0C, 0xDC, 0x48, 0x85, 0xC9, 0x74, 0x48 };

/*+++

 ExpFindHost search pattern

+++*/

BYTE g_ExpFindHost22000_22621[] = { 0x41, 0x0F, 0xB7, 0x0E };
BYTE g_ExpFindHost22631_27842[] = { 0x44, 0x89, 0x44, 0x24, 0x78 };

/*+++

 PnpDeviceClassNotifyList search pattern

+++*/

//
// mul ecx
//
BYTE g_PnpDeviceClassNotifyList_SubPattern_7601[] = { 0xF7, 0xE1 };

BYTE g_PnpDeviceClassNotifyList_SubPattern_9200[] = { 0xC1, 0xEA, 0x02, 0x6B, 0xD2, 0x0D };

//
//  shr edx, 2
//  imul eax, edx, 0Dh
//
BYTE g_PnpDeviceClassNofityList_SubPattern_9600_26080[] = { 0xC1, 0xEA, 0x02, 0x6B, 0xC2, 0x0D };
