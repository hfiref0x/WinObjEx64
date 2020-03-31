/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       EXCEPTH.H
*
*  VERSION:     1.85
*
*  DATE:        06 Mar 2020
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

#define WOBJ_EXCEPTION_FILTER exceptFilter(GetExceptionCode(), GetExceptionInformation())
#define WOBJ_EXCEPTION_FILTER_LOG exceptFilterWithLog(GetExceptionCode(), GetExceptionInformation())
