/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       WINE.C
*
*  VERSION:     1.82
*
*  DATE:        11 Nov 2019
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "ntos/ntldr.h"

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
const char *wine_get_version(void)
{
    pwine_get_version pfn = NULL;
    HMODULE hmod;
    RESOLVE_INFO rfn;

    hmod = GetModuleHandle(TEXT("ntdll.dll"));
    if (hmod) {

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


/*
* is_wine
*
* Purpose:
*
* Query if there is a Wine layer enabled.
*
* N.B. This function bypasses current WineStaging hide exports hack.
*
*/
int is_wine(void)
{
    pwine_get_version pfn = NULL;
    HMODULE hmod;
    RESOLVE_INFO rfn;

    hmod = GetModuleHandle(TEXT("ntdll.dll"));
    if (hmod) {

        if (NT_SUCCESS(NtRawGetProcAddress(
            (LPVOID)hmod,
            "wine_get_version",
            &rfn)))
        {
            if (rfn.ResultType == FunctionCode)
                pfn = (pwine_get_version)rfn.Function;
        }

        if (pfn)
            return 1;
    }
    return 0;
}
