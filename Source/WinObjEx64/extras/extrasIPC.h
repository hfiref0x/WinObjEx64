/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2018
*
*  TITLE:       EXTRASIPC.H
*
*  VERSION:     1.52
*
*  DATE:        08 Jan 2018
*
*  Common header file for InterProcess Communication mecahisms dialog.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef enum _IPC_DIALOG_MODE {
    IpcModeNamedPipes = 1,
    IpcModeMailshots = 2,
    IpcMaxMode
} IPC_DIALOG_MODE;

VOID extrasCreateIpcDialog(
    _In_ HWND hwndParent,
    _In_ IPC_DIALOG_MODE Mode);
