/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2018
*
*  TITLE:       EXTAPI.C
*
*  VERSION:     1.53
*
*  DATE:        07 Mar 2018
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

EXTENDED_API_SET g_ExtApiSet = { NULL, NULL };

/*
* ExApiSetInit
*
* Purpose:
*
* Initializes newest Windows version specific function pointers.
*
* Called once during supInit
*
*/
NTSTATUS ExApiSetInit(
    VOID
    )
{
    NTSTATUS Status = STATUS_SOME_NOT_MAPPED;
    HANDLE hNtdll = NULL;

    //
    // New Partition API introduced in Windows 10.
    //
    hNtdll = GetModuleHandle(TEXT("ntdll.dll"));
    if (hNtdll) {
        g_ExtApiSet.NtOpenPartition = (pfnNtOpenPartition)GetProcAddress(hNtdll, "NtOpenPartition");
        g_ExtApiSet.NtManagePartition = (pfnNtManagePartition)GetProcAddress(hNtdll, "NtManagePartition");

        if ((g_ExtApiSet.NtOpenPartition) &&
            (g_ExtApiSet.NtManagePartition))
            Status = STATUS_SUCCESS;
    }

    return Status;
}
