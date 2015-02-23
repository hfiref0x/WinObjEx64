/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       PROPBASICCONSTS.H
*
*  VERSION:     1.00
*
*  DATE:        13 Feb 2015
*
*  Consts header file for Basic property sheet.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

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