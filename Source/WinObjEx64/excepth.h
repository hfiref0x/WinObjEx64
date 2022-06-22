/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2022
*
*  TITLE:       EXCEPTH.H
*
*  VERSION:     2.00
*
*  DATE:        19 Jun 2022
*
*  Common header file for the exception handling routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

INT exceptFilter(
    _In_ UINT ExceptionCode,
    _In_ EXCEPTION_POINTERS *ExceptionPointers);

INT exceptFilterWithLog(
    _In_ UINT ExceptionCode,
    _In_opt_ EXCEPTION_POINTERS* ExceptionPointers);

INT exceptFilterUnhandled(
    _In_ struct _EXCEPTION_POINTERS* ExceptionInfo);

#define WOBJ_EXCEPTION_FILTER exceptFilter(GetExceptionCode(), GetExceptionInformation())
#define WOBJ_EXCEPTION_FILTER_LOG exceptFilterWithLog(GetExceptionCode(), GetExceptionInformation())
