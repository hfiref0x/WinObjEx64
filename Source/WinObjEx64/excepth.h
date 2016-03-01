/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2016
*
*  TITLE:       EXCEPTH.H
*
*  VERSION:     1.41
*
*  DATE:        01 Mar 2016
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
	_In_ EXCEPTION_POINTERS *ExceptionPointers
	);
