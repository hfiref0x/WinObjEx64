/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       WINE.C
*
*  VERSION:     1.73
*
*  DATE:        11 Mar 2019
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

const char *wine_get_version(void)
{
    pwine_get_version pfn;
    HMODULE hmod;

    hmod = GetModuleHandle(TEXT("ntdll.dll"));
    if (hmod) {
        pfn = (pwine_get_version)GetProcAddress(hmod, "wine_get_version");
        if (pfn)
            return pfn();
    }
    return NULL;
}

int is_wine(void)
{
    pwine_get_version pfn;
    HMODULE hmod;

    hmod = GetModuleHandle(TEXT("ntdll.dll"));
    if (hmod) {
        pfn = (pwine_get_version)GetProcAddress(hmod, "wine_get_version");
        if (pfn)
            return 1;
    }
    return 0;
}
