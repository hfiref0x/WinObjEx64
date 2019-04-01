/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       EXTRASPSLIST.H
*
*  VERSION:     1.73
*
*  DATE:        06 Mar 2019
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

#define MAX_KNOWN_WAITREASON 40
static LPWSTR T_WAITREASON[MAX_KNOWN_WAITREASON] = {
    L"Executive",
    L"FreePage",
    L"PageIn",
    L"PoolAllocation",
    L"DelayExecution",
    L"Suspended",
    L"UserRequest",
    L"WrExecutive",
    L"WrFreePage",
    L"WrPageIn",
    L"WrPoolAllocation",
    L"WrDelayExecution",
    L"WrSuspended",
    L"WrUserRequest",
    L"WrEventPair",
    L"WrQueue",
    L"WrLpcReceive",
    L"WrLpcReply",
    L"WrVirtualMemory",
    L"WrPageOut",
    L"WrRendezvous",
    L"WrKeyedEvent",
    L"WrTerminated",
    L"WrProcessInSwap",
    L"WrCpuRateControl",
    L"WrCalloutStack",
    L"WrKernel",
    L"WrResource",
    L"WrPushLock",
    L"WrMutex",
    L"WrQuantumEnd",
    L"WrDispatchInt",
    L"WrPreempted",
    L"WrYieldExecution",
    L"WrFastMutex",
    L"WrGuardedMutex",
    L"WrRundown",
    L"WrAlertByThreadId",
    L"WrDeferredPreempt",
    L"WrPhysicalFault"
};


VOID extrasCreatePsListDialog(
    _In_ HWND hwndParent);
