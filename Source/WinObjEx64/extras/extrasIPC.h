/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       EXTRASIPC.H
*
*  VERSION:     1.46
*
*  DATE:        09 Mar 2017
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
    IpcModeMailshots = 2
} IPC_DIALOG_MODE;

VOID extrasCreateIpcDialog(
    _In_ HWND hwndParent,
    _In_ IPC_DIALOG_MODE Mode
);
