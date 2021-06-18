/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2021
*
*  TITLE:       INSTDRV.H
*
*  VERSION:     1.90
*
*  DATE:        16 May 2021
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

BOOLEAN scmInstallDriver(
    _In_ SC_HANDLE SchSCManager,
    _In_ LPCTSTR DriverName,
    _In_opt_ LPCTSTR ServiceExe,
    _Out_opt_ PDWORD lpStatus);

BOOLEAN scmStartDriver(
    _In_ SC_HANDLE SchSCManager,
    _In_ LPCTSTR DriverName,
    _Out_opt_ PDWORD lpStatus);

BOOLEAN scmOpenDevice(
    _In_ LPCTSTR DriverName,
    _Out_opt_ PHANDLE lphDevice,
    _Out_opt_ PDWORD lpStatus);

BOOLEAN scmStopDriver(
    _In_ SC_HANDLE SchSCManager,
    _In_ LPCTSTR DriverName,
    _Out_opt_ PDWORD lpStatus);

BOOLEAN scmRemoveDriver(
    _In_ SC_HANDLE SchSCManager,
    _In_ LPCTSTR DriverName,
    _Out_opt_ PDWORD lpStatus);

BOOLEAN scmUnloadDeviceDriver(
    _In_ LPCTSTR Name,
    _Out_opt_ PDWORD lpStatus);

BOOLEAN scmLoadDeviceDriver(
    _In_ LPCTSTR Name,
    _In_opt_ LPCTSTR Path,
    _Out_opt_ PHANDLE lphDevice,
    _Out_opt_ PDWORD lpStatus);
