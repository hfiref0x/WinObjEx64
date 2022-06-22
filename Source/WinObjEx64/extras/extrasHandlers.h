/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2022
*
*  TITLE:       EXTRAS.H
*
*  VERSION:     2.00
*
*  DATE:        19 Jun 2022
*
*  Common header file for Extras dialogs handlers.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

VOID extrasCreateCallbacksDialog(
    VOID);

VOID extrasCreateCmOptDialog(
    VOID);

VOID extrasCreateDriversDialog(
    _In_ DRIVERS_DLG_MODE Mode);

VOID extrasCreateIpcDialog(
    _In_ IPC_DLG_MODE Mode);

VOID extrasCreatePNDialog(
    VOID);

VOID extrasCreatePsListDialog(
    VOID);

VOID extrasCreateSLCacheDialog(
    VOID);

VOID extrasCreateSSDTDialog(
    _In_ SSDT_DLG_MODE Mode);

VOID extrasCreateUsdDialog(
    VOID);
