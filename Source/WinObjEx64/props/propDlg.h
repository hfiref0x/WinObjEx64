/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       PROPDLG.H
*
*  VERSION:     1.83
*
*  DATE:        05 Jan 2020
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

//
// Externs for global properties variables.
//
extern HWND g_PropWindow;
extern HWND g_PsTokenWindow;
extern HWND g_PsPropWindow;
extern HWND g_DesktopPropWindow;
extern HWND g_NamespacePropWindow;

//
// Prototypes
//

BOOL propOpenCurrentObject(
    _In_ PROP_OBJECT_INFO *Context,
    _Out_ PHANDLE phObject,
    _In_ ACCESS_MASK DesiredAccess);

BOOL propCloseCurrentObject(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HANDLE hObject);

VOID propCreateDialog(
    _In_ PROP_DIALOG_CREATE_SETTINGS *Settings);

PPROP_OBJECT_INFO propContextCreate(
    _In_opt_ LPWSTR lpObjectName,
    _In_opt_ LPCWSTR lpObjectType,
    _In_opt_ LPWSTR lpCurrentObjectPath,
    _In_opt_ LPWSTR lpDescription);

VOID propContextDestroy(
    _In_ PROP_OBJECT_INFO *Context);
