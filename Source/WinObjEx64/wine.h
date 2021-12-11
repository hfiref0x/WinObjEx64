/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2021
*
*  TITLE:       WINE.H
*
*  VERSION:     1.92
*
*  DATE:        06 Dec 2021
*
*  Wine/Wine staging support header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

typedef char* (__cdecl *pwine_get_version)(void);

const char *wine_get_version(void);
int is_wine(void);
