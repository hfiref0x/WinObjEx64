/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2022
*
*  TITLE:       PROPDLG.H
*
*  VERSION:     2.00
*
*  DATE:        19 Jun 2022
*
*  Common header file for properties dialog.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

HWND propGetCommonWindow();
HWND propGetProcessesWindow();
HWND propGetThreadsWindow();
HWND propGetTokenWindow();
HWND propGetDesktopWindow();
HWND propGetNamespaceWindow();

_Success_(return)
BOOL propOpenCurrentObject(
    _In_ PROP_OBJECT_INFO *Context,
    _Out_ PHANDLE phObject,
    _In_ ACCESS_MASK DesiredAccess);

BOOL propCloseCurrentObject(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HANDLE hObject);

VOID propCreateDialog(
    _In_ PROP_CONFIG *Config);

PPROP_OBJECT_INFO propContextCreate(
    _In_ PROP_CONFIG* Config);

VOID propContextDestroy(
    _In_ PROP_OBJECT_INFO *Context);
