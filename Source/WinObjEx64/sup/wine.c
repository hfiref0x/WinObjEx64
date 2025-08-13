/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2025
*
*  TITLE:       WINE.C
*
*  VERSION:     2.09
*
*  DATE:        13 Aug 2025
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "ntos/ntldr.h"

#define _WINE_DEBUG_MODE
#undef _WINE_DEBUG_MODE

typedef char* (__cdecl* pwine_get_version)(void);

/*
* GetWineVersion
*
* Purpose:
*
* Query Wine version.
*
* N.B. This function bypasses current WineStaging hide exports hack.
*
*/
#ifndef _WINE_DEBUG_MODE
PCHAR GetWineVersion(
    VOID
)
{
    pwine_get_version pfn = NULL;
    HMODULE hmod;
    RESOLVE_INFO rfn;

    hmod = GetModuleHandle(TEXT("ntdll.dll"));
    if (hmod) {

        rfn.ForwarderName = NULL;
        rfn.Function = NULL;
        rfn.ResultType = FunctionCode;

        if (NT_SUCCESS(NtRawGetProcAddress(
            (LPVOID)hmod,
            "wine_get_version",
            &rfn)))
        {
            if (rfn.ResultType == FunctionCode)
                pfn = (pwine_get_version)rfn.Function;
        }

        if (pfn)
            return pfn();
    }
    return NULL;
}
#else
PCHAR GetWineVersion(
    VOID
)
{
    return "10.0";
}
#endif


/*
* IsWine
*
* Purpose:
*
* Query if there is a Wine layer enabled.
*
*/
BOOLEAN IsWine(
    VOID
)
{
    PCHAR lpWine;

    lpWine = GetWineVersion();

    return (lpWine != NULL);
}
