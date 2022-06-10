/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2022
*
*  TITLE:       WINE.C
*
*  VERSION:     1.94
*
*  DATE:        07 Jun 2022
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "ntos/ntldr.h"
#include "winedebug.h"

/*
* wine_get_version
*
* Purpose:
*
* Query Wine version.
*
* N.B. This function bypasses current WineStaging hide exports hack.
*
*/
#ifndef _WINE_DEBUG_MODE
const char* wine_get_version(void)
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
const char* wine_get_version(void)
{
    return "6.0";
}
#endif


/*
* is_wine
*
* Purpose:
*
* Query if there is a Wine layer enabled.
*
*/
int is_wine(void)
{
    CONST CHAR* szWine;

    szWine = wine_get_version();

    return (szWine != NULL);
}
