/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2016
*
*  TITLE:       PROPBASICCONSTS.H
*
*  VERSION:     1.44
*
*  DATE:        17 July 2016
*
*  Consts header file for Basic property sheet.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

//Calendar
LPCWSTR Months[12] = {
    L"Jan",
    L"Feb",
    L"Mar",
    L"Apr",
    L"May",
    L"Jun",
    L"Jul",
    L"Aug",
    L"Sep",
    L"Oct",
    L"Nov",
    L"Dec"
};

//OBJECT_HEADER Flags
LPCWSTR T_ObjectFlags[8] = {
    L"NewObject",
    L"KernelObject",
    L"KernelOnlyAccess",
    L"Exclusive",
    L"Permanent",
    L"DefSecurityQuota",
    L"SingleHandleEntry",
    L"DeletedInline"
};
