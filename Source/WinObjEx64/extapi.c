/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       EXTAPI.C
*
*  VERSION:     1.46
*
*  DATE:        03 Mar 2017
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
    HANDLE hNtdll = NULL;

    hNtdll = GetModuleHandle(TEXT("ntdll.dll"));
    if (hNtdll == NULL)
        return STATUS_UNSUCCESSFUL;

    g_ExtApiSet.NtOpenPartition = (pfnNtOpenPartition)GetProcAddress(hNtdll, "NtOpenPartition");      
    g_ExtApiSet.NtManagePartition = (pfnNtManagePartition)GetProcAddress(hNtdll, "NtManagePartition");
    return STATUS_SUCCESS;
}
