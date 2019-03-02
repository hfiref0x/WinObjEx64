/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019, portions (C) Mark Russinovich, FileMon
*
*  TITLE:       INSTDRV.H
*
*  VERSION:     1.72
*
*  DATE:        04 Feb 2019
*
*  Common header file for the program SCM usage.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

BOOL scmInstallDriver(
    _In_ SC_HANDLE SchSCManager,
    _In_ LPCTSTR DriverName,
    _In_opt_ LPCTSTR ServiceExe,
    _Out_opt_ PDWORD lpStatus);

BOOL scmStartDriver(
    _In_ SC_HANDLE SchSCManager,
    _In_ LPCTSTR DriverName,
    _Out_opt_ PDWORD lpStatus);

BOOL scmOpenDevice(
    _In_ LPCTSTR DriverName,
    _Out_opt_ PHANDLE lphDevice,
    _Out_opt_ PDWORD lpStatus);

BOOL scmStopDriver(
    _In_ SC_HANDLE SchSCManager,
    _In_ LPCTSTR DriverName,
    _Out_opt_ PDWORD lpStatus);

BOOL scmRemoveDriver(
    _In_ SC_HANDLE SchSCManager,
    _In_ LPCTSTR DriverName,
    _Out_opt_ PDWORD lpStatus);

BOOL scmUnloadDeviceDriver(
    _In_ LPCTSTR Name,
    _Out_opt_ PDWORD lpStatus);

BOOL scmLoadDeviceDriver(
    _In_ LPCTSTR Name,
    _In_opt_ LPCTSTR Path,
    _Out_opt_ PHANDLE lphDevice,
    _Out_opt_ PDWORD lpStatus);
